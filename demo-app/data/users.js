const bcrypt = require('bcryptjs');

// Pre-hashed password for "DemoPassword123!" using bcrypt (cost 10)
const demoPasswordHash = bcrypt.hashSync('DemoPassword123!', 10);

const users = [
  {
    id: 'user_synthetic_001',
    username: 'demo-user',
    passwordHash: demoPasswordHash,
  }
];

module.exports = {
  users,
};
