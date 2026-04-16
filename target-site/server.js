/**
 * NexMart — Target E-Commerce Site
 * Runs on port 3000. Sits behind the WAF (port 5000).
 * All requests reach here only after passing WAF inspection.
 */

const express = require("express");
const cors    = require("cors");
const path    = require("path");

const app  = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// ─── Fake product data ────────────────────────────────────────────────────────
const PRODUCTS = [
  { id: 1, name: "Wireless Pro Headphones",  price: 299.99, category: "Electronics", rating: 4.8, stock: 15, image: "🎧" },
  { id: 2, name: "Ultrabook Laptop 14\"",     price: 1299.99,category: "Electronics", rating: 4.6, stock: 8,  image: "💻" },
  { id: 3, name: "Running Shoes X1",          price: 119.99, category: "Sports",      rating: 4.7, stock: 32, image: "👟" },
  { id: 4, name: "Smart Watch Series 5",      price: 399.99, category: "Electronics", rating: 4.5, stock: 20, image: "⌚" },
  { id: 5, name: "Coffee Maker Pro",          price: 89.99,  category: "Home",        rating: 4.4, stock: 45, image: "☕" },
  { id: 6, name: "Yoga Mat Premium",          price: 49.99,  category: "Sports",      rating: 4.9, stock: 60, image: "🧘" },
  { id: 7, name: "Mechanical Keyboard",       price: 159.99, category: "Electronics", rating: 4.7, stock: 12, image: "⌨️"  },
  { id: 8, name: "Backpack Traveler 40L",     price: 79.99,  category: "Travel",      rating: 4.6, stock: 28, image: "🎒" },
];

const USERS = [
  { id: 1, username: "admin",   password: "admin123",   name: "Admin User",   role: "admin"    },
  { id: 2, username: "john",    password: "pass123",    name: "John Doe",     role: "customer" },
  { id: 3, username: "alice",   password: "alice2024",  name: "Alice Smith",  role: "customer" },
];

let COMMENTS = [
  { id: 1, productId: 1, user: "john",  text: "Amazing sound quality! Best purchase this year.", date: "2024-11-10" },
  { id: 2, productId: 1, user: "alice", text: "Comfortable and great noise cancellation.",        date: "2024-11-15" },
  { id: 3, productId: 3, user: "john",  text: "Perfect for marathon training.",                   date: "2024-11-20" },
];

let CONTACTS = [];
let loginAttempts = {};

// ─── Pages ────────────────────────────────────────────────────────────────────

app.get("/",            (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/products",    (req, res) => res.sendFile(path.join(__dirname, "public", "products.html")));
app.get("/login",       (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/contact",     (req, res) => res.sendFile(path.join(__dirname, "public", "contact.html")));
app.get("/cart",        (req, res) => res.sendFile(path.join(__dirname, "public", "cart.html")));

// ─── API: Products ────────────────────────────────────────────────────────────

app.get("/api/products", (req, res) => {
  const { search, category } = req.query;
  let results = [...PRODUCTS];
  if (category && category !== "all") {
    results = results.filter(p => p.category.toLowerCase() === category.toLowerCase());
  }
  if (search) {
    // intentionally "vulnerable" — WAF should catch injection attempts here
    results = results.filter(p =>
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      p.category.toLowerCase().includes(search.toLowerCase())
    );
  }
  res.json({ products: results, total: results.length, search: search || null });
});

app.get("/api/products/:id", (req, res) => {
  const product = PRODUCTS.find(p => p.id === parseInt(req.params.id));
  if (!product) return res.status(404).json({ error: "Product not found" });
  const comments = COMMENTS.filter(c => c.productId === product.id);
  res.json({ product, comments });
});

// ─── API: Login ───────────────────────────────────────────────────────────────

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const ip = req.headers["x-forwarded-for"] || req.ip;

  // Track login attempts per IP (WAF should catch this before it gets here)
  if (!loginAttempts[ip]) loginAttempts[ip] = 0;
  loginAttempts[ip]++;

  if (loginAttempts[ip] > 10) {
    return res.status(429).json({ error: "Too many login attempts. Please try again later." });
  }

  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).json({ error: "Invalid username or password.", attempts: loginAttempts[ip] });
  }

  loginAttempts[ip] = 0;
  res.json({ success: true, user: { id: user.id, name: user.name, role: user.role }, token: `fake-jwt-${user.id}-${Date.now()}` });
});

// ─── API: Comments ────────────────────────────────────────────────────────────

app.post("/api/comments", (req, res) => {
  const { productId, user, text } = req.body;
  if (!productId || !text) return res.status(400).json({ error: "productId and text are required" });

  // intentionally "vulnerable" — WAF should catch XSS attempts in text field
  const comment = {
    id: COMMENTS.length + 1,
    productId: parseInt(productId),
    user: user || "anonymous",
    text, // raw — WAF should sanitize before this
    date: new Date().toISOString().slice(0, 10),
  };
  COMMENTS.push(comment);
  res.status(201).json({ success: true, comment });
});

// ─── API: Contact ─────────────────────────────────────────────────────────────

app.post("/api/contact", (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) {
    return res.status(400).json({ error: "name, email, and message are required" });
  }
  const contact = { id: CONTACTS.length + 1, name, email, message, date: new Date().toISOString() };
  CONTACTS.push(contact);
  res.json({ success: true, message: "Thank you! We'll get back to you within 24 hours." });
});

// ─── API: Cart ────────────────────────────────────────────────────────────────

app.post("/api/cart/add", (req, res) => {
  const { productId, quantity } = req.body;
  const product = PRODUCTS.find(p => p.id === parseInt(productId));
  if (!product) return res.status(404).json({ error: "Product not found" });
  res.json({ success: true, message: `${product.name} added to cart`, product });
});

// ─── Health ───────────────────────────────────────────────────────────────────

app.get("/health", (req, res) => res.json({ status: "ok", site: "NexMart", port: PORT }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🛍️  NexMart target site running`);
  console.log(`   ✅ http://localhost:${PORT}`);
  console.log(`   🛡️  Behind WAF at http://localhost:5000\n`);
});
