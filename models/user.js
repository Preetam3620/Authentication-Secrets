const mongoose = require("mongoose");
const passportLocalMongoose = require("passport-local-mongoose").default;

const userSchema = new mongoose.Schema({
  email: String,
  secret: String,
  googleId: { type: String, unique: true, sparse: true },
});

// Keep the plugin's existing password hashing defaults so stored passwords work.
// Sparse indexes allow Google accounts to omit a local username and vice versa.
userSchema.plugin(passportLocalMongoose, { usernameUnique: false });
userSchema.index({ username: 1 }, { name: "username_unique_sparse", unique: true, sparse: true });

module.exports = mongoose.model("User", userSchema);
