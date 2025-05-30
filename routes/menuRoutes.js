const express = require('express');
const router = express.Router();
const MenuItem = require('../models/MenuItem');

// ✅ Get all menu items
router.get('/', async (req, res) => {
    const items = await MenuItem.find();
    res.json(items);
});

// ✅ Add/update menu items (Speech-to-text)
router.post('/update', async (req, res) => {
    const { name, quantity } = req.body;
    let item = await MenuItem.findOne({ name });

    if (item) {
        item.quantity += quantity;
    } else {
        item = new MenuItem({ name, quantity });
    }

    await item.save();
    res.json({ message: 'Menu updated', item });
});

// ✅ Decrease stock when an order is placed
router.post('/order', async (req, res) => {
    const { name, quantity } = req.body;
    let item = await MenuItem.findOne({ name });

    if (!item || item.quantity < quantity) {
        return res.status(400).json({ message: 'Not enough stock' });
    }

    item.quantity -= quantity;
    await item.save();
    res.json({ message: 'Order placed', item });
});

module.exports = router;
