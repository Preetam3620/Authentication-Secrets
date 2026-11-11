require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");
const User = require("../models/user");

async function migrateUserIndexes(userModel = User) {
  await userModel.createCollection();
  // Create the replacement indexes first. If existing data violates uniqueness,
  // MongoDB rejects the migration and the original indexes remain in place.
  await userModel.createIndexes();
  const indexes = await userModel.collection.indexes();
  for (const index of indexes) {
    if (Object.keys(index.key).length === 1 && index.key.username === 1 &&
        index.unique && !index.sparse) {
      await userModel.collection.dropIndex(index.name);
    }
  }
}

async function main() {
  try {
    await mongoose.connect(process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/userDB", {
      autoIndex: false,
    });
    await migrateUserIndexes();
    console.log("User indexes migrated. Existing accounts and password hashes were preserved.");
  } finally {
    await mongoose.disconnect();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error("Unable to migrate indexes:", error.message);
    process.exitCode = 1;
  });
}

module.exports = { migrateUserIndexes };
