require("dotenv").config({ quiet: true });

const path = require("node:path");
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const { Passport } = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const User = require("./models/user");

function createApp({ env = process.env, userModel = User, sessionStore } = {}) {
  if (!env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET must be set to a random secret.");
  }
  if (Boolean(env.CLIENT_ID) !== Boolean(env.CLIENT_SECRET)) {
    throw new Error("Set both CLIENT_ID and CLIENT_SECRET to enable Google sign-in.");
  }

  const app = express();
  const passport = new Passport();
  const googleEnabled = Boolean(env.CLIENT_ID && env.CLIENT_SECRET);
  const production = env.NODE_ENV === "production";

  app.set("views", path.join(__dirname, "views"));
  app.set("view engine", "ejs");
  if (production) app.set("trust proxy", 1);
  app.locals.googleEnabled = googleEnabled;

  app.use(express.static(path.join(__dirname, "public")));
  app.use("/vendor/bootstrap", express.static(path.join(__dirname, "node_modules/bootstrap/dist/css")));
  app.use("/vendor/fontawesome/css", express.static(path.join(__dirname, "node_modules/@fortawesome/fontawesome-free/css")));
  app.use("/vendor/fontawesome/webfonts", express.static(path.join(__dirname, "node_modules/@fortawesome/fontawesome-free/webfonts")));
  app.use(express.urlencoded({ extended: false }));
  app.use(session({
    secret: env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: { httpOnly: true, sameSite: "lax", secure: production },
  }));
  app.use(passport.initialize());
  app.use(passport.session());

  passport.use(userModel.createStrategy());
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      done(null, await userModel.findById(id) || false);
    } catch (error) {
      done(error);
    }
  });

  if (googleEnabled) {
    passport.use(new GoogleStrategy({
      clientID: env.CLIENT_ID,
      clientSecret: env.CLIENT_SECRET,
      callbackURL: env.GOOGLE_CALLBACK_URL || "http://localhost:3000/auth/google/secrets",
      state: true,
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        const user = await userModel.findOneAndUpdate(
          { googleId: profile.id },
          { $setOnInsert: { googleId: profile.id } },
          { upsert: true, returnDocument: "after", runValidators: true }
        );
        done(null, user);
      } catch (error) {
        done(error);
      }
    }));

    app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));
    app.get("/auth/google/secrets",
      passport.authenticate("google", { failureRedirect: "/login" }),
      (req, res) => res.redirect("/secrets")
    );
  }

  const requireAuthentication = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.redirect("/login");
  };

  app.get("/", (req, res) => res.render("home"));
  app.get("/login", (req, res) => res.render("login"));
  app.get("/register", (req, res) => res.render("register"));

  app.post("/logout", (req, res, next) => {
    req.logout((error) => {
      if (error) return next(error);
      req.session.destroy((error) => {
        if (error) return next(error);
        res.clearCookie("connect.sid");
        res.redirect("/");
      });
    });
  });

  app.get("/secrets", async (req, res) => {
    const usersWithSecrets = await userModel.find({ secret: { $ne: null } }).select("secret -_id");
    res.render("secrets", { usersWithSecrets });
  });

  app.get("/submit", requireAuthentication, (req, res) => res.render("submit"));
  app.post("/submit", requireAuthentication, async (req, res) => {
    const secret = req.body?.secret;
    if (typeof secret !== "string" || !secret.trim()) {
      return res.status(400).send("Enter a secret.");
    }
    req.user.secret = secret.trim();
    await req.user.save();
    res.redirect("/secrets");
  });

  app.post("/register", async (req, res, next) => {
    const { username, password } = req.body || {};
    if (typeof username !== "string" || !username.trim() ||
        typeof password !== "string" || !password) {
      return res.status(400).send("Email and password are required.");
    }
    let user;
    try {
      user = await userModel.register({ username: username.trim() }, password);
    } catch (error) {
      if (error.name === "UserExistsError" || error.code === 11000) {
        return res.redirect("/register");
      }
      throw error;
    }
    req.login(user, (error) => {
      if (error) return next(error);
      res.redirect("/secrets");
    });
  });

  app.post("/login",
    passport.authenticate("local", { failureRedirect: "/login" }),
    (req, res) => res.redirect("/secrets")
  );

  // Express 5 forwards rejected async route promises to this handler.
  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    console.error(error);
    res.status(error.status || 500).send("Unable to complete the request.");
  });

  return app;
}

async function start(env = process.env) {
  const app = createApp({ env });
  await mongoose.connect(env.MONGODB_URI || "mongodb://127.0.0.1:27017/userDB");
  try {
    const server = await new Promise((resolve, reject) => {
      const listener = app.listen(env.PORT || 3000, () => resolve(listener));
      listener.once("error", reject);
    });
    console.log(`Server listening on port ${server.address().port}.`);
    return server;
  } catch (error) {
    await mongoose.disconnect();
    throw error;
  }
}

if (require.main === module) {
  start().catch((error) => {
    console.error("Unable to start the server:", error.message);
    process.exitCode = 1;
  });
}

module.exports = { createApp, start };
