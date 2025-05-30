const mongoose = require('mongoose');

const trackSchema = new mongoose.Schema({
  blockName: { type: String, required: true, unique: true },
  status: { type: String, required: true },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Track", trackSchema);
