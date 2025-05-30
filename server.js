const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors'); // Import CORS
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const http = require('http');
const crypto = require('crypto'); // <<< ADD THIS LINE for signature verification
const User = require('./models/User'); // Adjust path if needed
require('dotenv').config();
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());

app.use(cors(
    //{
    //origin: 'http://localhost:3000', // Flutter Web or React frontend (keep this for browser access from localhost)
    // If your Flutter app is running on a different origin when built for web, update this.
    //credentials: true}
)); // Enable CORS

const JWT_SECRET = process.env.JWT_SECRET;
// In real app, keep it in .env
const Razorpay = require('razorpay');

const razorpayInstance = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});
const clientBlocks = new Map(); // key: WebSocket client, value: block string
// Use a more appropriate map name if it stores user-specific connections
const userConnections = new Map(); // key: rollNumber (string), value: WebSocket client

// IMPORTANT: Define sendUserOrderStatus BEFORE it's called
// (This function definition was in your second part, but it's called in the first part's WebSocket connection)
async function sendUserOrderStatus(rollNumber, specificStatus = null) {
    const userWs = userConnections.get(rollNumber);
    if (userWs && userWs.readyState === WebSocket.OPEN) {
        try {
            let statusToSend;

            if (specificStatus) {
                statusToSend = specificStatus;
                console.log(`DEBUG (sendUserOrderStatus): Using provided status '${specificStatus}' for ${rollNumber}`);
            } else {
                const latestOrder = await Order.findOne({ rollNumber: rollNumber })
                    .sort({ createdAt: -1 })
                    .limit(1);

                if (latestOrder) {
                    statusToSend = latestOrder.status;
                    console.log(`DEBUG (sendUserOrderStatus): Fetched latest order status for ${rollNumber}: ${latestOrder.status}`);
                } else {
                    statusToSend = "none";
                    console.log(`DEBUG (sendUserOrderStatus): No latest order found for ${rollNumber}. Setting status to 'none'.`);
                }
            }

            const message = JSON.stringify({
                userId: rollNumber,
                status: statusToSend
            });
            console.log(`Sending user banner update to ${rollNumber}: ${message}`);
            userWs.send(message);
        } catch (error) {
            console.error(`Error sending user order status to ${rollNumber}:`, error);
        }
    } else {
        console.log(`No active WebSocket connection for user: ${rollNumber} or WS not open.`);
    }
}


wss.on('connection', (ws, req) => {
    console.log('A new client connected');

    ws.on('message', async (message) => { // Made async because sendUserOrderStatus is async
        try {
            const parsed = JSON.parse(message);
            if (parsed.type === 'register' && parsed.userId) {
                userConnections.set(parsed.userId, ws);
                console.log(`User ${parsed.userId} registered WebSocket connection.`);
                await sendUserOrderStatus(parsed.userId); // Await this call
            } else if (parsed.type === 'set_block') {
                clientBlocks.set(ws, parsed.blockName);
                console.log(`Client assigned to block: ${parsed.blockName}`);
            }
        } catch (err) {
            console.error('Error parsing message:', err);
        }
    });

    ws.on('close', () => {
        clientBlocks.delete(ws);
        for (let [userId, clientWs] of userConnections.entries()) {
            if (clientWs === ws) {
                userConnections.delete(userId);
                console.log(`User ${userId} disconnected.`);
                break;
            }
        }
        console.log('Client disconnected');
    });

    ws.on('error', error => {
        console.error('WebSocket error:', error);
    });

    // sendInitialBlockOrderUpdates(ws); // You have this, keep it for staff dashboard
});

// MongoDB Models (Keep these as they are)
const MenuItem = mongoose.model('MenuItem', new mongoose.Schema({
    name: String,
    quantity: Number
}));
const Order = mongoose.model('Order', new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    items: [{
        name: String,
        quantity: Number,
        price: Number
    }],
    rollNumber: String,
    blockSelection: String,
    amount: Number,
    status: { type: String, enum: ['placed', 'confirmed', 'preparing', 'on_the_way', 'delivered', 'cancelled'], default: 'placed' },
    address: String,
    paymentStatus: { type: String, enum: ['pending', 'paid', 'failed'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
}));
const Payment = mongoose.model('Payment', new mongoose.Schema({
    transactionId: String,
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: Number,
    status: { type: String, enum: ['success', 'failed'], default: 'success' },
    blockSelection: String,
    date: { type: Date, default: Date.now }
}));

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Access Denied: No Token Provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or Expired Token' });

        req.user = user;
        next();
    });
}

app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const userRollNumber = req.user.rollNumber;
        const user = await User.findOne({ rollNumber: userRollNumber });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({
            rollNumber: user.rollNumber,
            // Add other profile information you want to send
        });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Assuming this function is defined later in your full code.
// For now, let's include a placeholder or ensure it's defined before it's called in storePaymentDetails
const decrementStock = async (items) => {
    // This is a placeholder. You need to ensure FoodItem is correctly mapped to MenuItem
    // or adjust your schema. Assuming 'MenuItem' is the correct model for food items/stock.
    try {
        for (const item of items) {
            const result = await MenuItem.findOneAndUpdate( // Changed from FoodItem to MenuItem
                { name: item.name }, // Find by name, assuming unique names
                { $inc: { quantity: -item.quantity } }, // $inc for quantity
                { new: true }
            );
            if (!result) {
                console.error(`Item ${item.name} not found for stock decrement.`);
                return { success: false, error: `Item ${item.name} not found.` };
            }
            if (result.quantity < 0) {
                 console.warn(`Stock for ${item.name} went negative (${result.quantity}). Resetting to 0.`);
                 await MenuItem.updateOne({ name: item.name }, { quantity: 0 });
            }
        }
        return { success: true };
    } catch (err) {
        console.error("Stock update error:", err);
        return { success: false, error: err.message };
    }
};


// CORRECTED app.post('/storePaymentDetails', ...) route
app.post('/storePaymentDetails', authenticateToken, async (req, res) => {
    console.log("Received /storePaymentDetails request body:", req.body); // Added for debugging
    const {
        transactionId, // This might be used for your Payment model's transactionId
        amount,
        status, // This 'status' is from Flutter, which might be 'success' or 'failed'
        items,
        blockSelection,
        razorpay_payment_id,    // <<< Expected from Flutter
        razorpay_order_id,      // <<< Expected from Flutter
        razorpay_signature      // <<< Expected from Flutter
    } = req.body;

    // --- CRITICAL: Signature Verification ---
    // Perform verification ONLY if razorpay_payment_id, razorpay_order_id, razorpay_signature are present
    if (razorpay_payment_id && razorpay_order_id && razorpay_signature) {
        const generatedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(razorpay_order_id + "|" + razorpay_payment_id)
            .digest('hex');

        if (generatedSignature !== razorpay_signature) {
            console.error("❌ Razorpay Signature verification failed!");
            return res.status(400).json({ message: "Signature verification failed" });
        }
        console.log("✅ Razorpay Signature verified successfully.");
    } else {
        // If these crucial fields are missing, it's either not a Razorpay payment or an incomplete request
        console.warn("❗ Missing Razorpay signature details. Proceeding without signature verification (not recommended for production).");
        // You might want to return an error here in production:
        // return res.status(400).json({ message: "Missing Razorpay payment verification details." });
    }
    // --- END Signature Verification ---

    // Basic input validation (still important)
    if (!amount || !items || items.length === 0 || !blockSelection) {
        return res.status(400).json({ message: "Required order details are incomplete." });
    }

    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ message: "User not found for authenticated token" });
        }

        // Save the payment details to the database (use razorpay_payment_id as transactionId)
        const payment = new Payment({
            transactionId: razorpay_payment_id || transactionId, // Use Razorpay ID if available
            user: req.user._id,
            amount,
            status: 'success', // If signature verified, or if no signature, assume client status
            blockSelection
        });
        await payment.save();
        console.log(`DEBUG (storePaymentDetails): Payment saved with status: 'success'`);

        // Create an Order (if payment is successful based on verification or client status)
        // Ensure you only create an order if the payment is genuinely successful
        // (which the signature verification helps confirm)
        if (status === 'success' || (razorpay_signature && generatedSignature === razorpay_signature)) {
            const rollNumber = user.rollNumber;
            const address = `${rollNumber} - ${blockSelection}`;

            const order = new Order({
                user: req.user._id,
                items,
                rollNumber,
                blockSelection,
                amount,
                address,
                paymentStatus: 'paid',
                status: 'placed' // Explicitly set to 'placed' here for a new order
            });

            await order.save();
            console.log(`DEBUG (storePaymentDetails): New Order saved with status: '${order.status}' for rollNumber: ${rollNumber}`);

            // Broadcast new order to all connected clients (e.g., staff dashboard)
            const orderSummary = {
                _id: order._id, // Include order ID for staff to identify
                rollNumber,
                blockSelection,
                address,
                amount,
                items,
                createdAt: order.createdAt,
                status: order.status
            };
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify({ type: 'new_order', data: orderSummary }));
                }
            });
            console.log(`DEBUG (storePaymentDetails): Broadcasted new order to all clients.`);

            // 🚀 Send a specific update to the user who placed the order
            if (user.rollNumber) {
                await sendUserOrderStatus(user.rollNumber, order.status);
                console.log(`DEBUG (storePaymentDetails): Triggered sendUserOrderStatus for ${user.rollNumber} with status '${order.status}'`);
            }

            const stockUpdateResponse = await decrementStock(items);
            if (!stockUpdateResponse.success) {
                console.error("❌ Error decrementing stock after successful payment:", stockUpdateResponse.error);
                // Decide how to handle this: potentially revert order, notify admin, etc.
                // For now, we'll still return success for payment but log the stock issue.
            }

            return res.status(201).json({ message: "Payment & Order successful", payment, orderId: order._id }); // return orderId for frontend
        } else {
            // This else block would be hit if client status was not 'success' AND signature verification failed/wasn't performed
            return res.status(400).json({ message: "Payment status not successful or verification failed" });
        }
    } catch (error) {
        console.error("❌ Error in storing payment details:", error);
        return res.status(500).json({ message: "Server error during payment processing" });
    }
});

const Track = require('./models/trackSchema'); // or correct path

// Update or create status for a block
// This is the route you mentioned in your Flutter code that the UpdationPage calls
app.post('/updateTrackStatus', async (req, res) => {
    const { blockName, status } = req.body; // 'blockName' will be 'A', 'B', 'C', 'D' from your Flutter UpdationPage

    console.log(`[REQUEST RECEIVED] POST /updateTrackStatus - blockName: ${blockName}, status: ${status}`);

    if (!blockName || !status) {
        console.log('[ERROR] Missing blockName or status in request.');
        return res.status(400).json({ message: 'Missing blockName or status' });
    }

    try {
        // 1. Update the Track schema (for staff dashboard to see overall block status)
        await Track.findOneAndUpdate(
            { blockName: blockName },
            { status: status },
            { upsert: true, new: true }
        );
        console.log(`[SUCCESS] Track status for Block ${blockName} updated to: ${status}`);

        // 2. BROADCAST (staff specific)
        if (typeof broadcastBlockOrderStatus === 'function') {
             broadcastBlockOrderStatus(blockName, status);
             console.log(`[WS BROADCAST] Sent staff broadcast for Block ${blockName}.`);
        } else {
             console.warn("broadcastBlockOrderStatus function not found. WebSocket broadcast for staff not sent.");
        }

        // *************************************************************************
        // ********************** THE CRUCIAL PART: LINKING TO USER ORDERS *********
        // *************************************************************************

        // MODIFICATION HERE: Use regex to find orders where 'address' contains the block name
        // Example: if blockName is 'A', it will look for 'Block A' in the address field
        const regexBlockName = new RegExp(`Block ${blockName}$`); // '$' ensures it's at the end, or adjust regex if it can be anywhere
        console.log(`[ORDER QUERY] Attempting to find orders where address matches regex: "${regexBlockName}" and paymentStatus: 'paid'`);

        // 3. Find ALL INDIVIDUAL ORDERS that belong to this block
        const affectedOrders = await Order.find({
            address: { $regex: regexBlockName }, // Use $regex for pattern matching
            paymentStatus: 'paid'
        });
        console.log(`[ORDER QUERY RESULT] Found ${affectedOrders.length} paid orders in Block ${blockName} to update.`);

        // If no orders were found, we know the problem is the query itself (e.g., blockSelection mismatch)
        if (affectedOrders.length === 0) {
            console.warn(`[ORDER UPDATE SKIP] No matching paid orders found for Block ${blockName}. Skipping Order.updateMany and sendUserOrderStatus.`);
            res.status(200).json({ message: `Status updated for Block ${blockName}, but no matching paid orders found.` });
            return; // Exit here if no orders to update
        }

        // 4. Update the 'status' for all these individual orders in the Order schema
        await Order.updateMany(
            {
                address: { $regex: regexBlockName }, // Use $regex again for the updateMany filter
                paymentStatus: 'paid'
            },
            { $set: { status: status } }
        );
        console.log(`[SUCCESS] Status updated for all ${affectedOrders.length} paid orders in Block ${blockName} to: ${status}`);

        // 5. For EACH affected order, send a real-time WebSocket update to the respective USER
        if (typeof sendUserOrderStatus === 'function') {
            for (const order of affectedOrders) {
                if (order.rollNumber) {
                    await sendUserOrderStatus(order.rollNumber, status);
                    console.log(`[WS USER] Sent user banner update for rollNumber ${order.rollNumber} to status: ${status}`);
                } else {
                    console.warn(`[WS USER] Order ${order._id} found in block ${blockName} but has no rollNumber. Skipping user update.`);
                }
            }
        } else {
             console.warn("sendUserOrderStatus function not found. User banner updates not sent.");
        }

        // *************************************************************************

        res.status(200).json({ message: `Status updated for Block ${blockName} and its orders.` });

    } catch (error) {
        console.error(`[ERROR] Error updating track status and orders for Block ${blockName}:`, error);
        res.status(500).json({ message: 'Failed to update status', error });
    }
});


// Get status for a block
app.get("/getTrackStatus/:blockName", async (req, res) => {
    const { blockName } = req.params;

    try {
        const track = await Track.findOne({ blockName });
        if (!track) {
            return res.status(404).json({ message: "Block not found" });
        }
        res.json(track); // sends back blockName, status, updatedAt
    } catch (err) {
        console.error("Error fetching track:", err);
        res.status(500).json({ error: err.message });
    }
});

// Initialize 4 default blocks: A, B, C, D
app.post("/initTrackBlocks", async (req, res) => {
    const blocks = ['A', 'B', 'C', 'D'];
    try {
        for (const blockName of blocks) {
            await Track.updateOne(
                { blockName },
                { $setOnInsert: { status: "", updatedAt: new Date() } },
                { upsert: true }
            );
        }
        res.json({ success: true, message: "Blocks initialized." });
    } catch (err) {
        console.error("Error initializing blocks:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});
// Get status for all blocks
app.get("/getAllTrackStatus", async (req, res) => {
    try {
        const blocks = await Track.find().sort({ blockName: 1 });
        res.json(blocks);
    } catch (err) {
        console.error("Error fetching all track statuses:", err);
        res.status(500).json({ error: err.message });
    }
});


app.post('/checkStock', async (req, res) => {
    try {
        const items = req.body.items;
        if (!Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ message: 'Invalid request. Items missing.' });
        }

        const unavailableItems = [];

        for (const item of items) {
            const menuItem = await MenuItem.findOne({ name: item.name });

            if (!menuItem) {
                unavailableItems.push({ name: item.name, reason: "This item is currently unavailable" });
            } else if (menuItem.quantity < item.quantity) {
                unavailableItems.push({
                    name: item.name,
                    reason: `Only ${menuItem.quantity} left in stock`
                });
            }
        }

        if (unavailableItems.length > 0) {
            return res.status(200).json({ available: false, issues: unavailableItems });
        }

        return res.status(200).json({ available: true });
    } catch (err) {
        console.error("Check stock error:", err);
        return res.status(500).json({ message: "Server error" });
    }
});


// Route to get all menu items in stock
app.get('/getStock', async (req, res) => {
    try {
        const items = await MenuItem.find({});
        res.status(200).json({ items });
    } catch (err) {
        console.error("Error fetching stock:", err);
        res.status(500).json({ message: "Server error" });
    }
});


// Route to update stock (for canteen staff)
app.post('/updateStock', authenticateToken, async (req, res) => {
    console.log("📩 Received request:", req.body);

    const { item, quantity, action } = req.body;

    if (!item || quantity === undefined || !action) {
        return res.status(400).json({ message: "Missing required fields" });
    }

    try {
        let menuItem = await MenuItem.findOne({ name: item });

        if (!menuItem) {
            if (action === "add") {
                menuItem = new MenuItem({ name: item, quantity: quantity });
                await menuItem.save();
                console.log(`🆕 Created new item ${item} with quantity ${quantity}`);

                return res.status(200).json({ message: "New item created and stock updated", item: menuItem });
            } else {
                return res.status(400).json({ success: false, error: `Cannot remove from non-existing item: ${item}` });
            }
        }

        console.log(`🔹 Before Update: ${menuItem.name} has ${menuItem.quantity}`);
        if (action === "add") {
            menuItem.quantity += quantity;
        } else if (action === "remove") {
            if (menuItem.quantity < quantity) {
                return res.status(400).json({ success: false, error: `Insufficient stock for ${item}` });
            }
            menuItem.quantity -= quantity;
        } else {
            return res.status(400).json({ message: "Invalid action type" });
        }

        await menuItem.save();
        console.log(`✅ After Update: ${menuItem.name} now has ${menuItem.quantity}`);


        res.status(200).json({ message: "Stock updated", item: menuItem });

    } catch (err) {
        console.error("❌ Server Error:", err);
        res.status(500).json({ message: "Server error" });
    }
});


// Assuming you already have your menu model
app.post('/reduceStock', async (req, res) => {
    try {
        const { name, quantity } = req.body;

        if (!name || !quantity) {
            return res.status(400).json({ message: 'Name and quantity are required' });
        }

        // Find the menu item by name in the 'menuitems' collection
        const item = await MenuItem.findOne({ name: name });

        if (!item) {
            return res.status(404).json({ message: 'Item not found' });
        }

        // Decrease the quantity in stock by the purchased quantity
        item.quantity -= quantity;

        // Ensure quantity doesn't go negative
        if (item.quantity < 0) {
            item.quantity = 0;
        }

        // Save the updated item back to the database
        await item.save();

        res.status(200).json({ message: 'Stock updated successfully' });
    } catch (err) {
        console.error("Error reducing stock:", err);
        res.status(500).json({ message: 'Server error' });
    }
});


// Signup route for new users
app.post('/signup', async (req, res) => {
    const { rollNumber, password, role } = req.body;
    if (!rollNumber || !password) {
        return res.status(400).json({ message: "Roll number and password are required" });
    }

    try {
        const existingUser = await User.findOne({ rollNumber });
        if (existingUser) {
            return res.status(409).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userRole = role === 'staff' ? 'staff' : 'customer';

        const user = new User({ rollNumber, password: hashedPassword, role: userRole });
        await user.save();

        res.status(201).json({ message: "Signup successful" });
    } catch (err) {
        console.error("Signup error:", err);
        res.status(500).json({ message: "Server error" });
    }
});
// Login route for users
app.post('/login', async (req, res) => {
    const { rollNumber, password } = req.body;

    try {
        // Hardcoded staff login (consider moving this to a secure config or staff user in DB)
        if (rollNumber === "23bdcanteen" && password === "v43372jjha") {
            const token = jwt.sign({ rollNumber, isStaff: true, _id: 'staff-user-id' }, JWT_SECRET, { expiresIn: '1h' }); // Added a placeholder _id
            return res.json({ message: "Canteen staff login successful", token, isStaff: true });
        }

        const user = await User.findOne({ rollNumber });
        if (!user) return res.status(401).json({ message: "Invalid credentials" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

        // Ensure _id is included in the token for regular users as well
        const token = jwt.sign({ rollNumber: user.rollNumber, _id: user._id, isStaff: false }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: "Login successful", token, isStaff: false });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// Express route for creating Razorpay order
app.post('/api/payment/create-order', async (req, res) => {
    try {
        const { amount } = req.body;

        if (!amount || isNaN(amount) || amount <= 0) { // Added amount validation
            return res.status(400).json({ message: "Amount is required and must be a positive number" });
        }

        // Razorpay accepts amount in paise (INR * 100)
        const options = {
            amount: amount * 100, // ₹100 => 10000 paise
            currency: "INR",
            receipt: `receipt_order_${Date.now()}`,
            // You can add notes here if needed:
            // notes: {
            //     userId: req.user._id.toString(), // If you have authenticateToken here
            //     rollNumber: req.user.rollNumber // If you have authenticateToken here
            // }
        };

        const order = await razorpayInstance.orders.create(options);

        if (!order) {
            return res.status(500).json({ message: "Failed to create Razorpay order" });
        }

        // Send order details to frontend
        res.status(200).json({
            success: true,
            orderId: order.id,
            amount: order.amount,
            currency: order.currency,
        });
    } catch (err) {
        console.error("❌ Error creating Razorpay order:", err);
        res.status(500).json({ message: "Server error while creating order" });
    }
});

// Route to get a user's past orders
app.get('/user/orders', authenticateToken, async (req, res) => {
    try {
        // Using req.user._id from the authenticated token
        const userOrders = await Order.find({ user: req.user._id }).sort({ createdAt: -1 });
        res.status(200).json({ orders: userOrders });
    } catch (err) {
        console.error("Error fetching user orders:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// Route to get all paid orders grouped by block (for staff dashboard view without track status)
app.get('/staff/getBlockOrders', async (req, res) => { // Removed authenticateToken if this is for public facing staff view
    try {
        const allOrders = await Order.find({ paymentStatus: 'paid' }).sort({ createdAt: -1 }); // Added sort for consistency

        const blockOrders = {};
        const blockStatuses = {}; // This will hold the current status of the latest order in each block

        allOrders.forEach(order => {
            let block = order.blockSelection;

            // If blockSelection is missing, try to infer from address
            if (!block && order.address) {
                // Assuming address format like "ROLLNUM - Block X"
                const addressParts = order.address.split(' - ');
                if (addressParts.length > 1 && addressParts[1].startsWith('Block ')) {
                    block = addressParts[1];
                } else if (addressParts.length > 0 && ['A', 'B', 'C', 'D'].includes(addressParts[addressParts.length - 1])) {
                    // Fallback for just block name if it's the last part
                    block = `Block ${addressParts[addressParts.length - 1]}`;
                } else {
                    block = 'Unknown'; // If no Block info in address
                }
            } else if (!block) {
                block = 'Unknown'; // If both blockSelection and address are missing or don't match pattern
            }

            if (!blockOrders[block]) blockOrders[block] = [];
            blockOrders[block].push(order);
            // The logic here is that the last order processed (due to sort) dictates the block status,
            // but for a true block status, you should rely on the 'Track' model.
            // This 'blockStatuses' here will reflect the status of the *last order encountered* for that block.
            blockStatuses[block] = order.status || 'placed'; // Default to 'placed'
        });

        res.json({ blockOrders, blockStatuses });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching orders', error });
    }
});

// Route to get all paid orders grouped by block WITH their current track status
app.get('/staff/getBlockOrdersWithTrackStatus', async (req, res) => { // Removed authenticateToken as well here if it's a public staff view
    try {
        const allOrders = await Order.find({ paymentStatus: 'paid' }).sort({ createdAt: -1 }); // Sort to get latest status per order
        const tracks = await Track.find(); // Fetch all track statuses

        const blockOrders = {};
        const blockStatuses = {}; // This will hold the status from the Track model for each block

        // Map block name to status from tracks
        const trackStatusMap = {};
        tracks.forEach(track => {
            // Ensure block name matches the expected format, e.g., "Block A"
            trackStatusMap[`Block ${track.blockName}`] = track.status;
            trackStatusMap[track.blockName] = track.status; // Also map without "Block " prefix
        });

        allOrders.forEach(order => {
            let block = order.blockSelection;

            if (!block && order.address) {
                const addressParts = order.address.split(' - ');
                if (addressParts.length > 1 && addressParts[1].startsWith('Block ')) {
                    block = addressParts[1];
                } else if (addressParts.length > 0 && ['A', 'B', 'C', 'D'].includes(addressParts[addressParts.length - 1])) {
                    block = `Block ${addressParts[addressParts.length - 1]}`;
                } else {
                    block = 'Unknown';
                }
            } else if (!block) {
                block = 'Unknown';
            }

            if (!blockOrders[block]) blockOrders[block] = [];
            blockOrders[block].push(order);

            // Use the status from the Track model if available, otherwise default
            blockStatuses[block] = trackStatusMap[block] || trackStatusMap[block.replace('Block ', '')] || 'No status available';
        });

        res.json({ blockOrders, blockStatuses });
    } catch (error) {
        console.error("Error fetching orders with track status:", error); // Added specific logging
        res.status(500).json({ message: 'Error fetching orders with track status', error });
    }
});

// This route was duplicated. We will keep the one that updates the 'Track' model and individual orders.
// The other duplicated one that only updated 'Order' status is removed.
// The app.post("/updateTrackStatus") from the previous response already handles this.
// So, effectively, this section here is removed because it's redundant.
/*
app.post('/staff/updateBlockStatus', async (req, res) => {
    const { block, status } = req.body;

    if (!block || !status) {
        return res.status(400).json({ message: 'Missing data' });
    }

    // THIS IS THE REDUNDANT PART:
    // blockStatuses[block] = status; // This 'blockStatuses' is not defined globally and is not persistent
    // await Order.updateMany({ block: block }, { $set: { status: status } }); // This is handled by updateTrackStatus
    // io.emit('blockStatusUpdated', { block, status }); // 'io' is not defined, use wss instead

    res.status(200).json({ message: 'Status updated' });
});
*/

// Route to mark orders as delivered (This logic seems to update 'Track' not 'Order')
// If the intention is to mark specific *orders* as delivered, this should update the 'Order' model.
// If it's to mark a whole 'Track' entry as delivered, then the model should match.
// Assuming this is to mark individual orders as delivered, it should use the Order model.
app.post('/markOrdersDelivered', authenticateToken, async (req, res) => { // Added auth for staff action
    if (!req.user.isStaff) return res.status(403).json({ message: 'Access denied' });

    const { orderIds } = req.body;

    if (!Array.isArray(orderIds) || orderIds.length === 0) { // Added check for empty array
        return res.status(400).json({ error: 'orderIds must be a non-empty array' });
    }

    try {
        // Update the status of the specific orders to 'delivered'
        const result = await Order.updateMany( // Changed from Track to Order
            { _id: { $in: orderIds } }, // Use _id for Order model
            { $set: { status: 'delivered' } }
        );

        // After updating, notify the relevant users via WebSocket
        const updatedOrders = await Order.find({ _id: { $in: orderIds } });
        for (const order of updatedOrders) {
            if (order.rollNumber) {
                await sendUserOrderStatus(order.rollNumber, order.status); // Send updated status
            }
        }


        res.json({ message: 'Orders marked as delivered', updated: result.modifiedCount });
    } catch (err) {
        console.error('Error marking delivered:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Example: decrementStock function for MongoDB
// This function was already defined in the previous section.
// Ensure it's only defined once in your file.
// I'll leave it here as a comment block just to show the corrected version.
/*
const decrementStock = async (items) => {
    try {
        for (const item of items) {
            const result = await MenuItem.findOneAndUpdate( // Corrected to MenuItem
                { name: item.name },
                { $inc: { quantity: -item.quantity } },
                { new: true }
            );
            if (!result) {
                console.error(`Item ${item.name} not found for stock decrement.`);
                return { success: false, error: `Item ${item.name} not found.` };
            }
            if (result.quantity < 0) {
                 console.warn(`Stock for ${item.name} went negative (${result.quantity}). Resetting to 0.`);
                 await MenuItem.updateOne({ name: item.name }, { quantity: 0 });
            }
        }
        return { success: true };
    } catch (err) {
        console.error("Stock update error:", err);
        return { success: false, error: err.message };
    }
};
*/

// Order confirmation route (This route seems redundant given storePaymentDetails creates the order)
// If storePaymentDetails already creates the order, this route is likely not needed.
// It could be used for a different flow, but as it stands, it duplicates order creation.
// I recommend reviewing your frontend flow. If payment is successful and then storePaymentDetails is called,
// then this /api/order/confirm might be unnecessary.
app.post('/api/order/confirm', authenticateToken, async (req, res) => {
    const { orderId, items, rollNumber, blockSelection, address, amount } = req.body;
    try {
        // Option 1: Find existing order and update (if orderId is from previous step)
        const existingOrder = await Order.findById(orderId);
        if (existingOrder) {
            // If order already exists, maybe just update its status if needed
            existingOrder.status = 'confirmed'; // Or whatever status is appropriate
            existingOrder.paymentStatus = 'paid';
            await existingOrder.save();
            console.log(`Order ${orderId} updated to confirmed.`);
            // You might not need to decrement stock again if it was done during payment.
            // If not, then:
            // const stockUpdateResponse = await decrementStock(items);
            // if (!stockUpdateResponse.success) { ... }
            return res.status(200).json({ message: "Order confirmed and updated", order: existingOrder });
        }

        // Option 2: Create a new order if not found (less ideal, implies missing a step)
        const order = new Order({
            _id: orderId, // Use the orderId generated by your frontend/payment gateway
            user: req.user._id, // Use authenticated user ID
            items,
            rollNumber,
            blockSelection,
            address,
            amount,
            status: 'confirmed', // Update status if needed
            paymentStatus: 'paid' // Assuming payment was successful before this confirmation
        });

        await order.save();

        // Optionally, decrement stock here as well if not done during payment
        const stockUpdateResponse = await decrementStock(items); // Ensure decrementStock is defined

        if (stockUpdateResponse.success) {
            res.status(200).json({ message: "Order confirmed and stock updated", order });
        } else {
            console.error("❌ Stock update failed during order confirmation:", stockUpdateResponse.error);
            res.status(500).json({ message: "Order confirmed, but stock update failed" });
        }
    } catch (err) {
        console.error("Order confirmation error:", err);
        res.status(500).json({ message: "Server error" });
    }
});


// WebSocket setup for order updates and block order updates
// IMPORTANT: You had a duplicate wss.on('connection') at the top.
// THIS ENTIRE BLOCK BELOW IS REDUNDANT AND SHOULD BE REMOVED.
// The main wss.on('connection') at the top of your file already handles everything.
/*
wss.on('connection', ws => {
    console.log('Client connected to WebSocket');

    ws.on('close', () => {
        console.log('Client disconnected from WebSocket');
    });

    ws.on('error', error => {
        console.error('WebSocket error:', error);
    });

    // Send initial block order data to the newly connected client
    sendBlockOrderUpdates(ws);
});
*/

// Function to send block order updates via WebSocket (for staff dashboard)
async function sendBlockOrderUpdates(client) {
    try {
        const allOrders = await Order.find({ paymentStatus: 'paid' }).sort({ createdAt: -1 }); // Sort for consistency
        const tracks = await Track.find(); // Fetch track statuses if needed for display

        const blockOrders = {};
        const blockStatuses = {}; // This will hold the current status from the Track model for each block

        // Map block name to status from tracks
        const trackStatusMap = {};
        tracks.forEach(track => {
            trackStatusMap[track.blockName] = track.status;
            trackStatusMap[`Block ${track.blockName}`] = track.status; // Store with "Block " prefix too
        });

        allOrders.forEach(order => {
            let block = order.blockSelection;
            if (!block && order.address) {
                const addressParts = order.address.split(' - ');
                if (addressParts.length > 1 && addressParts[1].startsWith('Block ')) {
                    block = addressParts[1];
                } else if (addressParts.length > 0 && ['A', 'B', 'C', 'D'].includes(addressParts[addressParts.length - 1])) {
                    block = `Block ${addressParts[addressParts.length - 1]}`;
                } else {
                    block = 'Unknown';
                }
            } else if (!block) {
                block = 'Unknown';
            }

            if (!blockOrders[block]) blockOrders[block] = [];
            blockOrders[block].push(order);
            // Use status from Track model if available
            blockStatuses[block] = trackStatusMap[block] || trackStatusMap[block.replace('Block ', '')] || 'No status available';
        });

        client.send(JSON.stringify({ type: 'blockOrders', data: { blockOrders, blockStatuses } }));
    } catch (error) {
        console.error('Error fetching and sending block order updates:', error);
    }
}

// Function to broadcast updated block order status to all connected clients
// This function is fine, but the route calling it below is the duplicate one.
async function broadcastBlockOrderStatus(block, status) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: 'blockStatusUpdate', data: { block, status } }));
        }
    });
}

// Route to update block status and broadcast the update
// This route was duplicated. The correct one is `app.post("/updateTrackStatus")` from the previous correction.
// This block should be removed.
/*
app.post('/staff/updateBlockStatus', async (req, res) => {
    const { block, status } = req.body;

    try {
        await Order.updateMany(
            { blockSelection: block },
            { $set: { status: status } }
        );
        res.status(200).json({ message: 'Status updated for block ' + block });
        broadcastBlockOrderStatus(block, status); // Broadcast the update
    } catch (error) {
        res.status(500).json({ message: 'Failed to update block status', error });
    }
});
*/

// Route to get all orders for the staff dashboard (today's orders)
app.get('/staff/orders', authenticateToken, async (req, res) => {
    if (!req.user.isStaff) return res.status(403).json({ message: 'Access denied' });

    try {
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0); // Start of the day

        const orders = await Order.find({
            createdAt: { $gte: todayStart },
            paymentStatus: 'paid' // Only show paid orders
        }).sort({ createdAt: -1 });

        res.status(200).json({ orders });
    } catch (err) {
        console.error("Error fetching today's orders:", err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Function to send current order status to a specific user
// This function is a duplicate definition. It's already defined at the very top of the file
// after the initial imports and before `wss.on('connection')`.
// THIS ENTIRE BLOCK SHOULD BE REMOVED.
/*
async function sendUserOrderStatus(rollNumber, specificStatus = null) {
    const userWs = userConnections.get(rollNumber);
    if (userWs && userWs.readyState === WebSocket.OPEN) {
        try {
            let statusToSend;
            if (specificStatus) {
                statusToSend = specificStatus;
                console.log(`DEBUG (sendUserOrderStatus): Using provided status '${specificStatus}' for ${rollNumber}`);
            } else {
                const latestOrder = await Order.findOne({ rollNumber: rollNumber })
                    .sort({ createdAt: -1 })
                    .limit(1);

                if (latestOrder) {
                    statusToSend = latestOrder.status;
                    console.log(`DEBUG (sendUserOrderStatus): Fetched latest order status for ${rollNumber}: ${latestOrder.status}`);
                } else {
                    statusToSend = "none";
                    console.log(`DEBUG (sendUserOrderStatus): No latest order found for ${rollNumber}. Setting status to 'none'.`);
                }
            }
            const message = JSON.stringify({
                userId: rollNumber,
                status: statusToSend
            });
            console.log(`Sending user banner update to ${rollNumber}: ${message}`);
            userWs.send(message);
        } catch (error) {
            console.error(`Error sending user order status to ${rollNumber}:, error`);
        }
    } else {
        console.log(`No active WebSocket connection for user: ${rollNumber} or WS not open.`);
    }
}
*/

// Route to get details of a specific order for the staff
app.get('/staff/orders/:orderId', authenticateToken, async (req, res) => {
    if (!req.user.isStaff) return res.status(403).json({ message: 'Access denied' });
    const { orderId } = req.params;

    try {
        const order = await Order.findById(orderId);
        if (!order) {
            return res.status(404).json({ message: 'Order not found' });
        }
        res.status(200).json(order);
    } catch (err) {
        console.error('Error fetching order details:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Route to update the status of a specific order (for staff)
app.patch('/staff/orders/:orderId', authenticateToken, async (req, res) => {
    if (!req.user.isStaff) return res.status(403).json({ message: 'Access denied' });
    const { orderId } = req.params;
    const { status } = req.body;
   console.log(`[STAFF PATCH] Received update request for Order ID: ${orderId}, new status: ${status}`);

    if (!status || !['placed', 'confirmed', 'preparing', 'on_the_way', 'delivered', 'cancelled'].includes(status)) { // Added 'placed' for completeness
        return res.status(400).json({ message: 'Invalid order status' });
    }

    try {
        const updatedOrder = await Order.findByIdAndUpdate(orderId, { status }, { new: true });
        if (!updatedOrder) {
            return res.status(404).json({ message: 'Order not found' });
        }

        res.status(200).json({ message: 'Order status updated', order: updatedOrder });

        // IMPORTANT: Broadcast this specific user's order status update
        if (updatedOrder.rollNumber) {
            await sendUserOrderStatus(updatedOrder.rollNumber, status); // Call the new function
        }

    } catch (err) {
        console.error('Error updating order status:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Route to get order statistics for the staff dashboard
app.get('/staff/orderStats', authenticateToken, async (req, res) => {
    if (!req.user.isStaff) {
        return res.status(403).json({ message: 'Access denied' });
    }

    try {
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);
        const todayEnd = new Date();
        todayEnd.setHours(23, 59, 59, 999);

        const receivedOrders = await Order.countDocuments({
            createdAt: { $gte: todayStart, $lte: todayEnd },
            paymentStatus: 'paid',
            status: { $ne: 'cancelled' } // Don't count cancelled orders as received
        });

        const completedOrders = await Order.countDocuments({
            createdAt: { $gte: todayStart, $lte: todayEnd },
            paymentStatus: 'paid',
            status: 'delivered'
        });

        const todayOrders = await Order.find({
            createdAt: { $gte: todayStart, $lte: todayEnd },
            paymentStatus: 'paid'
        });

        let todayTotal = 0;
        todayOrders.forEach(order => {
            todayTotal += order.amount;
        });

        res.status(200).json({
            received: receivedOrders,
            completed: completedOrders,
            todayTotal: todayTotal.toFixed(2)
        });
    } catch (err) {
        console.error("Error fetching order statistics:", err);
        res.status(500).json({ message: 'Server error fetching order statistics' });
    }
});

// For the orders page - get orders by block
app.get('/getOrdersByBlock/:blockName', async (req, res) => {
    const blockName = req.params.blockName;
    try {
        const orders = await Order.find({ blockSelection: blockName }); // Assuming blockName is stored directly
        if (orders.length > 0) {
            res.json(orders);
        } else {
            res.status(404).json({ message: 'No orders found for this block' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Error fetching orders', error: error.toString() });
    }
});

const OrderHistoryModel = require('./models/Orders'); // Make sure this path is correct and it's the 'Order' model

app.get('/orderHistory', authenticateToken, async (req, res) => {
    try {
        const userId = req.user._id;
        // Ensure OrderHistoryModel is actually your Order model if it's the same data
        const orderHistory = await Order.find({ user: userId }).sort({ createdAt: -1 }); // Changed to Order model
        res.status(200).json(orderHistory);
    } catch (error) {
        console.error('Error fetching order history:', error);
        res.status(500).json({ message: 'Failed to fetch order history' });
    }
});

const Settings = require('./models/Settings'); // Make sure this path is correct

app.get('/dashboardStats', async (req, res) => {
    try {
        // Total number of orders
        const total = await Order.countDocuments();

        // Get today's start and end times
        const startOfDay = new Date();
        startOfDay.setHours(0, 0, 0, 0);

        const endOfDay = new Date();
        endOfDay.setHours(23, 59, 59, 999);

        // Get today's orders
        const todayOrders = await Order.find({
            createdAt: { $gte: startOfDay, $lte: endOfDay },
            paymentStatus: 'paid' // Only consider paid orders for revenue
        });

        // Calculate today's total revenue
        const todayTotal = todayOrders.reduce((sum, order) => sum + (order.amount || 0), 0);

        // Send only total orders and today's revenue
        res.json({
            total, // total number of orders ever
            todayTotal // total amount (revenue) today
        });
    } catch (err) {
        console.error('Dashboard stats error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// GET current toggle value for ordering status
app.get('/ordering-status', async (req, res) => {
    try {
        let settings = await Settings.findOne();
        if (!settings) {
            // If no settings exist, create with default enabled
            settings = await Settings.create({ isOrderingEnabled: true });
        }
        res.json({ isOrderingEnabled: settings.isOrderingEnabled });
    } catch (err) {
        console.error("Error fetching ordering status:", err); // Added error logging
        res.status(500).json({ error: 'Server error' });
    }
});

// POST to update toggle value for ordering status
app.post('/set-ordering-status', authenticateToken, async (req, res) => { // Added authenticateToken
    if (!req.user.isStaff) return res.status(403).json({ message: 'Access denied' }); // Only staff can change this

    const { isOrderingEnabled } = req.body;
    // Basic type validation
    if (typeof isOrderingEnabled !== 'boolean') {
        return res.status(400).json({ error: 'Invalid value for isOrderingEnabled. Must be boolean.' });
    }
    try {
        let settings = await Settings.findOne();
        if (!settings) {
            settings = await Settings.create({ isOrderingEnabled });
        } else {
            settings.isOrderingEnabled = isOrderingEnabled;
            await settings.save();
        }
        res.json({ success: true, isOrderingEnabled });
    } catch (err) {
        console.error("Error setting ordering status:", err); // Added error logging
        res.status(500).json({ error: 'Failed to update status' });
    }
});

let todaySpecialEnabled = false; // This is a simple in-memory flag.
                                // For persistence across server restarts, store in DB.

app.get('/today-special-status', (req, res) => {
    res.json({ isTodaySpecialEnabled: todaySpecialEnabled });
});

app.post('/set-today-special-status', authenticateToken, (req, res) => { // Added authenticateToken
    if (!req.user.isStaff) return res.status(403).json({ message: 'Access denied' }); // Only staff can change this

    const { isTodaySpecialEnabled } = req.body;
    if (typeof isTodaySpecialEnabled === 'boolean') {
        todaySpecialEnabled = isTodaySpecialEnabled;
        res.status(200).json({ message: 'Today special status updated', isTodaySpecialEnabled }); // Send JSON response
    } else {
        res.status(400).json({ error: 'Invalid payload: isTodaySpecialEnabled must be a boolean' });
    }
});


// Start the server, listening on the specified IP address
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        server.listen(process.env.PORT || 5000, () => { // Removed '192.168.29.90'
    console.log(`🚀 Server running on port ${process.env.PORT || 5000}`); // Updated console log
});
    })
    .catch(err => console.error("❌ MongoDB connection error:", err));