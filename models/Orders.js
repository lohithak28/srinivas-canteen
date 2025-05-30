// models/Order.js (Mongoose model)
const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  items: Array,
  rollNumber: String,
  amount: Number,
  status: String,
  address: String,
  paymentStatus: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Orders', orderSchema);
