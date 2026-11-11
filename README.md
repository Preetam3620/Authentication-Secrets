# Authentication Secrets

An Express application for sharing secrets anonymously, with local accounts and optional Google sign-in.

## Setup

Use Node.js 26 LTS (selected by `.nvmrc`) and a maintained MongoDB installation (MongoDB 8.x recommended). Node.js 24 LTS is also supported.

```sh
npm ci
cp .env.example .env
```

On PowerShell, use `Copy-Item .env.example .env`. Set `SESSION_SECRET` to a long random value and `MONGODB_URI` to your MongoDB connection string, then run:

```sh
npm start
```

The default URL is http://localhost:3000. `npm run dev` enables Node's built-in watch mode.

Google authentication is optional. To enable it, set both `CLIENT_ID` and `CLIENT_SECRET`, and register the exact `GOOGLE_CALLBACK_URL` in Google Cloud Console. The local default is `http://localhost:3000/auth/google/secrets`. Use your HTTPS origin for a deployed instance. OAuth state verification is enabled.

For production, set `NODE_ENV=production`, serve HTTPS behind one trusted reverse proxy, and provide a persistent `express-session` store through `createApp({ sessionStore })`. The default in-memory store is for local development and loses sessions on restart. The application waits for MongoDB to connect before accepting requests and exits with an error if startup fails.

## Upgrading an existing database

The hardcoded Atlas hostname and Heroku callback URL have been removed. Replace `MONGO_USER` / `MONGO_PWD` configuration with the full `MONGODB_URI`, set `SESSION_SECRET`, and configure `GOOGLE_CALLBACK_URL` if Google sign-in is enabled.

With the application stopped, run this once against the existing database before starting the new version:

```sh
npm run migrate:indexes
```

This creates unique sparse indexes for `username` and `googleId`, then removes the legacy non-sparse username index. Multiple Google accounts can omit a local username. The migration preserves all user documents, secrets, salts, and password hashes and can be rerun. If duplicate Google IDs exist, index creation fails before the old username index is removed; resolve those duplicates before retrying. New empty databases create the indexes automatically.

Local password hashing keeps the original plugin defaults (PBKDF2, SHA-256, 25,000 iterations, 512-byte key) so existing users can still sign in. Logout now uses `POST /logout`; templates submit the corresponding form.

## Dependency migration

Latest stable npm `latest` tags were checked on **2026-11-11**, using the package pages and the live [npm registry](https://registry.npmjs.org/). `package-lock.json` records the exact installed dependency tree. Prerelease tags were excluded.

| Original dependency | Latest checked | Result |
| --- | --- | --- |
| [bcrypt](https://www.npmjs.com/package/bcrypt) | 6.0.0 | Removed: unused; the app uses Passport Local Mongoose's PBKDF2 hashing. |
| [body-parser](https://www.npmjs.com/package/body-parser) | 2.4.0 | Replaced direct usage with built-in `express.urlencoded()`. Express resolves the current parser transitively. |
| [dotenv](https://www.npmjs.com/package/dotenv) | 18.0.10 | Updated. |
| [ejs](https://www.npmjs.com/package/ejs) | 7.0.2 | Updated; all templates render in integration tests. |
| [express](https://www.npmjs.com/package/express) | 5.3.0 | Updated; async route failures reach the error handler. |
| [express-session](https://www.npmjs.com/package/express-session) | 1.19.0 | Updated; secret comes from configuration. |
| [md5](https://www.npmjs.com/package/md5) | 2.3.0 | Removed: unused. |
| [mongoose](https://www.npmjs.com/package/mongoose) | 9.12.1 | Updated; promises replace query/save callbacks and obsolete connection/index options were removed. |
| [mongoose-encryption](https://www.npmjs.com/package/mongoose-encryption) | 2.1.2 | Removed: unused. |
| [mongoose-findorcreate](https://www.npmjs.com/package/mongoose-findorcreate) | 4.0.0 | Replaced with indexed atomic `findOneAndUpdate()` upserts. |
| [passport](https://www.npmjs.com/package/passport) | 0.7.0 | Updated; authenticate before establishing a session and use callback-based logout. |
| [passport-google-oauth20](https://www.npmjs.com/package/passport-google-oauth20) | 2.0.0 | Already latest; enabled state verification and configurable callback URL. |
| [passport-local](https://www.npmjs.com/package/passport-local) | 1.0.0 | Already latest; supplied transitively by Passport Local Mongoose. |
| [passport-local-mongoose](https://www.npmjs.com/package/passport-local-mongoose) | 9.2.1 | Updated; use its default export and promise-based registration. |

The browser assets are now npm dependencies served locally: [Bootstrap 5.3.9](https://www.npmjs.com/package/bootstrap) and [Font Awesome 7.3.1](https://www.npmjs.com/package/@fortawesome/fontawesome-free). Templates use Bootstrap 5 utilities in place of removed jumbotron, form-group, and block-button classes. The old Bootstrap Social stylesheet was removed.

Migration references: [Express 5](https://expressjs.com/en/guide/migrating-5/), [Mongoose 6](https://mongoosejs.com/docs/migrating_to_6.html), [Mongoose 7](https://mongoosejs.com/docs/migrating_to_7.html), [Mongoose 8](https://mongoosejs.com/docs/migrating_to_8.html), [Mongoose 9](https://mongoosejs.com/docs/migrating_to_9.html), [Passport logout](https://www.passportjs.org/concepts/authentication/logout/), [Passport Local Mongoose](https://github.com/saintedlama/passport-local-mongoose), and [Bootstrap 5](https://getbootstrap.com/docs/5.3/migration/).

## Verification

```sh
npm test
npm audit
npm outdated
```

Tests use Node's built-in test runner and [mongodb-memory-server 11.3.0](https://www.npmjs.com/package/mongodb-memory-server) to run a temporary real MongoDB instance. The first run may download a MongoDB binary into `node_modules/.cache`; it needs network access. No production database or real Google credentials are used. Only Google's token/profile responses are mocked; the tests exercise the OAuth routes, state, sessions, and database operations.

Coverage includes local registration/login, legacy password hashes, duplicate/invalid registrations, session invalidation, anonymous submission guards, saved/escaped secrets, EJS templates, local styles/fonts, Google account upserts, database errors, and the existing-database index migration.
