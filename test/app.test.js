const assert = require("node:assert/strict");
const { pbkdf2 } = require("node:crypto");
const { once } = require("node:events");
const path = require("node:path");
const { promisify } = require("node:util");
const { after, before, test } = require("node:test");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const { createApp } = require("../app");
const User = require("../models/user");
const { migrateUserIndexes } = require("../scripts/migrate-indexes");

const env = { SESSION_SECRET: "test-session-secret", NODE_ENV: "test" };
let database;
let server;
let baseUrl;

function client(url = baseUrl) {
  let cookie = "";
  return async (route, { form, ...options } = {}) => {
    const response = await fetch(`${url}${route}`, {
      redirect: "manual",
      ...options,
      method: form ? "POST" : options.method || "GET",
      headers: { cookie, ...options.headers },
      body: form ? new URLSearchParams(form) : undefined,
    });
    for (const value of response.headers.getSetCookie()) {
      if (value.startsWith("connect.sid=")) cookie = value.split(";")[0];
    }
    return response;
  };
}

function assertRedirect(response, location) {
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), location);
}

before(async () => {
  database = await MongoMemoryServer.create({
    binary: { downloadDir: path.join(__dirname, "../node_modules/.cache/mongodb-memory-server") },
  });
  await mongoose.connect(database.getUri());
  await User.init();
  server = createApp({ env }).listen(0, "127.0.0.1");
  await once(server, "listening");
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
  await mongoose.disconnect();
  if (database) await database.stop();
});

test("configuration requires a session secret and paired OAuth credentials", () => {
  assert.throws(() => createApp({ env: {} }), /SESSION_SECRET/);
  assert.throws(() => createApp({ env: { ...env, CLIENT_ID: "only-id" } }), /both/);
});

test("public pages render with the current EJS engine and local styles", async () => {
  const request = client();
  for (const route of ["/", "/login", "/register", "/secrets"]) {
    const response = await request(route);
    assert.equal(response.status, 200, route);
    const html = await response.text();
    assert.equal((html.match(/<!DOCTYPE html>/g) || []).length, 1);
    assert.match(html, /<\/html>/);
    assert.doesNotMatch(html, /href="\/auth\/google"/);
  }
  for (const route of ["/vendor/bootstrap/bootstrap.min.css", "/vendor/fontawesome/css/all.min.css",
    "/vendor/fontawesome/webfonts/fa-solid-900.woff2", "/css/styles.css"]) {
    assert.equal((await request(route)).status, 200, route);
  }
  assert.equal((await request("/auth/google")).status, 404);
});

test("both secret submission routes require authentication", async () => {
  const request = client();
  assertRedirect(await request("/submit"), "/login");
  assertRedirect(await request("/submit", { form: { secret: "unauthorized" } }), "/login");
  assert.equal(await User.countDocuments({ secret: "unauthorized" }), 0);
});

test("registration, session deserialization, secret saving, and logout work", async () => {
  const request = client();
  const registration = await request("/register", {
    form: { username: "alice@example.com", password: "correct-password" },
  });
  assertRedirect(registration, "/secrets");
  const cookie = registration.headers.get("set-cookie");
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /SameSite=Lax/i);
  const user = await User.findOne({ username: "alice@example.com" }).select("+hash +salt");
  assert.ok(user.hash && user.salt);
  assert.equal(user.password, undefined);
  assert.equal((await request("/submit")).status, 200);
  assert.equal((await request("/submit", { form: { secret: "  " } })).status, 400);
  assert.equal((await request("/submit", {
    method: "POST", headers: { "content-type": "application/json" },
  })).status, 400);
  const secret = '<script>alert("secret")</script>';
  assertRedirect(await request("/submit", { form: { secret } }), "/secrets");
  assert.equal((await User.findById(user.id)).secret, secret);
  const html = await (await client()("/secrets")).text();
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /alice@example.com|<script>/);
  assert.equal((await request("/logout")).status, 404);
  assertRedirect(await request("/logout", { method: "POST" }), "/");
  assertRedirect(await request("/submit"), "/login");
  // The old cookie must no longer authenticate either.
  assertRedirect(await client()("/submit", {
    headers: { cookie: cookie.split(";")[0] },
  }), "/login");
});

test("invalid credentials never establish a login session", async () => {
  const request = client();
  for (const form of [
    { username: "alice@example.com", password: "wrong" },
    { username: "missing@example.com", password: "wrong" },
    {},
  ]) {
    assertRedirect(await request("/login", { form }), "/login");
    assertRedirect(await request("/submit"), "/login");
  }
});

test("valid credentials authenticate an existing account", async () => {
  const request = client();
  assertRedirect(await request("/login", {
    form: { username: "alice@example.com", password: "correct-password" },
  }), "/secrets");
  assert.equal((await request("/submit")).status, 200);
});

test("duplicate and malformed registrations do not overwrite an account", async () => {
  const request = client();
  assertRedirect(await request("/register", {
    form: { username: "alice@example.com", password: "replacement" },
  }), "/register");
  assertRedirect(await request("/submit"), "/login");
  for (const form of [{}, { username: " " }, { username: "user@example.com" },
    { username: "user@example.com", password: "" }]) {
    assert.equal((await request("/register", { form })).status, 400);
  }
  assert.equal(await User.countDocuments({ username: "alice@example.com" }), 1);
});

test("password hashes from the original plugin defaults still authenticate", async () => {
  const salt = "0123456789abcdef".repeat(4);
  const hash = await promisify(pbkdf2)("legacy-password", salt, 25000, 512, "sha256");
  await User.collection.insertOne({ username: "legacy@example.com", salt, hash: hash.toString("hex") });
  const request = client();
  assertRedirect(await request("/login", {
    form: { username: "legacy@example.com", password: "legacy-password" },
  }), "/secrets");
  assert.equal((await request("/submit")).status, 200);
});

test("deleted session users are treated as logged out", async () => {
  const request = client();
  assertRedirect(await request("/register", {
    form: { username: "deleted@example.com", password: "password" },
  }), "/secrets");
  await User.deleteOne({ username: "deleted@example.com" });
  assertRedirect(await request("/submit"), "/login");
});

test("Google OAuth checks state and creates or reuses separate accounts", async (t) => {
  // Stub only Google's token/profile responses; exercise real Passport middleware,
  // cookies, state verification, and database writes through the HTTP routes.
  const probe = new GoogleStrategy({
    clientID: "test-id", clientSecret: "test-secret", callbackURL: "http://localhost/callback",
  }, () => {});
  const tokens = t.mock.method(Object.getPrototypeOf(probe._oauth2), "getOAuthAccessToken",
    (code, params, done) => done(null, code, "refresh-token", {}));
  t.mock.method(GoogleStrategy.prototype, "userProfile", (token, done) => {
    done(null, { id: token, provider: "google" });
  });
  const oauthServer = createApp({ env: {
    ...env, CLIENT_ID: "test-id", CLIENT_SECRET: "test-secret",
    GOOGLE_CALLBACK_URL: "http://localhost/auth/google/secrets",
  } }).listen(0, "127.0.0.1");
  await once(oauthServer, "listening");
  t.after(async () => {
    oauthServer.closeAllConnections();
    await new Promise((resolve) => oauthServer.close(resolve));
  });
  const url = `http://127.0.0.1:${oauthServer.address().port}`;
  assert.match(await (await client(url)("/login")).text(), /href="\/auth\/google"/);

  const invalid = client(url);
  await invalid("/auth/google");
  assertRedirect(await invalid("/auth/google/secrets?code=forged&state=invalid"), "/login");
  assert.equal(tokens.mock.callCount(), 0);
  assertRedirect(await invalid("/submit"), "/login");

  for (const googleId of ["google-one", "google-one", "google-two"]) {
    const request = client(url);
    const authorization = await request("/auth/google");
    assert.equal(authorization.status, 302);
    const location = new URL(authorization.headers.get("location"));
    assert.equal(location.origin, "https://accounts.google.com");
    assert.equal(location.searchParams.get("redirect_uri"), "http://localhost/auth/google/secrets");
    const state = location.searchParams.get("state");
    assert.ok(state);
    assertRedirect(await request(`/auth/google/secrets?code=${googleId}&state=${state}`), "/secrets");
    assert.equal((await request("/submit")).status, 200);
    assertRedirect(await request("/submit", { form: { secret: googleId } }), "/secrets");
  }
  assert.equal(await User.countDocuments({ googleId: { $exists: true } }), 2);
  assert.equal(await User.countDocuments({ googleId: "google-one" }), 1);
});

test("Express 5 forwards rejected database operations to the error handler", async (t) => {
  t.mock.method(User, "find", () => {
    throw new Error("database unavailable");
  });
  t.mock.method(console, "error", () => {});
  const response = await client()("/secrets");
  assert.equal(response.status, 500);
  assert.equal(await response.text(), "Unable to complete the request.");
});

test("legacy username indexes migrate without changing accounts or hashes", async () => {
  const migrationUser = mongoose.model("MigrationUser", User.schema.clone(), "migration_users");
  await migrationUser.init();
  await migrationUser.collection.dropIndex("username_unique_sparse");
  await migrationUser.collection.createIndex({ username: 1 }, { unique: true, name: "username_1" });
  await migrationUser.collection.insertMany([
    { username: "legacy@example.com", hash: "existing-hash", salt: "existing-salt" },
    { googleId: "legacy-google-account" },
  ]);
  const before = await migrationUser.collection.find().toArray();
  await migrateUserIndexes(migrationUser);
  await migrateUserIndexes(migrationUser); // Safe to run more than once.
  assert.deepEqual(await migrationUser.collection.find().toArray(), before);
  const indexes = await migrationUser.collection.indexes();
  assert.ok(indexes.some((index) => index.name === "username_unique_sparse" && index.unique && index.sparse));
  assert.ok(!indexes.some((index) => index.name === "username_1"));
  await migrationUser.collection.insertOne({ googleId: "another-google-account" });
  await assert.rejects(migrationUser.collection.insertOne({ username: "legacy@example.com" }), { code: 11000 });
});
