const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  rollNumber: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['staff', 'customer'], default: 'customer' } // 👈 role field
});

module.exports = mongoose.model('User', userSchema);