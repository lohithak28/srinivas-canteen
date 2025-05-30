// models/Settings.js
const mongoose = require('mongoose');

const SettingsSchema = new mongoose.Schema({
  isOrderingEnabled: { type: Boolean, default: true }
});

module.exports = mongoose.model('Settings', SettingsSchema);
