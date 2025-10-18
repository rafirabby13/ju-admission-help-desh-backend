import express from "express";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import dotenv from "dotenv";
import cors from "cors";
import { GoogleGenAI } from "@google/genai";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const app = express();
const port = 5000;
dotenv.config();

app.use(express.json());
// allow 3000 and 5173
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://localhost:5173",
      process.env.FRONTEND_URL?.replace(/\/$/, ""),
    ].filter(Boolean),
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    optionsSuccessStatus: 204,
  })
);
// rely on cors middleware to handle preflight automatically

const uri = process.env.DB_URL;
console.log(uri);

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let feedbackCollection;
let usersCollection;
let qaCategoriesCollection;
let qaQuestionsCollection;
let noticesCollection;
let chatsCollection;
let isConnected = false;

async function connectToDatabase() {
  if (isConnected) {
    return {
      feedbackCollection,
      usersCollection,
      qaCategoriesCollection,
      qaQuestionsCollection,
      noticesCollection,
      chatsCollection,
    };
  }

  try {
    await client.connect();
    const db = client.db("admission");
    feedbackCollection = db.collection("feedback");
    usersCollection = db.collection("users");
    qaCategoriesCollection = db.collection("qa_categories");
    qaQuestionsCollection = db.collection("qa_questions");
    noticesCollection = db.collection("notices");
    chatsCollection = db.collection("chats");
    isConnected = true;

    // Seed super admin
    await seedSuperAdmin();

    console.log("Successfully connected to MongoDB!");
    return {
      feedbackCollection,
      usersCollection,
      qaCategoriesCollection,
      qaQuestionsCollection,
      noticesCollection,
      chatsCollection,
    };
  } catch (error) {
    console.error("Database connection error:", error);
    throw error;
  }
}

async function seedSuperAdmin() {
  try {
    const adminEmail = process.env.SUPER_ADMIN_EMAIL;
    const adminPassword = process.env.SUPER_ADMIN_PASSWORD;
    if (!adminEmail || !adminPassword) {
      console.log(
        "Skipping SUPER_ADMIN seed (missing SUPER_ADMIN_EMAIL/PASSWORD)"
      );
      return;
    }
    const existingAdmin = await usersCollection.findOne({ email: adminEmail });
    if (existingAdmin) {
      console.log("SUPER_ADMIN exists");
      return;
    }
    const { passwordHash, passwordSalt } = hashPassword(adminPassword);
    const superAdmin = {
      name: "Super Admin",
      email: adminEmail,
      phone: "",
      role: "SUPER_ADMIN",
      passwordHash,
      passwordSalt,
      isActive: true,
      createdAt: new Date(),
    };
    await usersCollection.insertOne(superAdmin);
    console.log("SUPER_ADMIN created");
  } catch (error) {
    console.error("Error seeding super admin:", error);
  }
}

// Auth utils
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .pbkdf2Sync(password, salt, 310000, 32, "sha256")
    .toString("hex");
  return { passwordHash: hash, passwordSalt: salt };
}

function verifyPassword(password, salt, expectedHash) {
  const hash = crypto
    .pbkdf2Sync(password, salt, 310000, 32, "sha256")
    .toString("hex");
  return crypto.timingSafeEqual(
    Buffer.from(hash, "hex"),
    Buffer.from(expectedHash, "hex")
  );
}

function signJwt(payload, expiresIn = "7d") {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET not configured");
  return jwt.sign(payload, secret, { expiresIn });
}

function verifyJwt(token) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET not configured");
  return jwt.verify(token, secret);
}

// Middleware
async function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const decoded = verifyJwt(token);
    await connectToDatabase();
    const user = await usersCollection.findOne({
      _id: new ObjectId(decoded.sub),
      isActive: { $ne: false },
    });
    if (!user) return res.status(401).json({ message: "Invalid token" });
    req.user = { id: user._id.toString(), email: user.email, role: user.role };
    next();
  } catch (e) {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden" });
    }
    next();
  };
}

// Routes
app.get("/", (req, res) => {
  res.send("Welcome to My Classroom");
});

// Auth routes
app.post("/api/auth/register", async (req, res) => {
  try {
    await connectToDatabase();
    const { name, email, phone, password, roll, session, registration, board } =
      req.body || {};
    if (
      !name ||
      !email ||
      !password ||
      !roll ||
      !session ||
      !registration ||
      !board
    )
      return res.status(400).json({ message: "Missing required fields" });
    const existing = await usersCollection.findOne({
      $or: [{ email }, { registration }],
    });
    if (existing)
      return res.status(409).json({ message: "Email already registered" });
    const { passwordHash, passwordSalt } = hashPassword(password);
    const userDoc = {
      name,
      email,
      phone: phone || "",
      roll,
      session,
      registration,
      board,
      role: "STUDENT",
      passwordHash,
      passwordSalt,
      isActive: true,
      createdAt: new Date(),
    };
    const result = await usersCollection.insertOne(userDoc);
    const token = signJwt({
      sub: result.insertedId.toString(),
      role: "STUDENT",
    });
    return res.json({
      token,
      user: {
        id: result.insertedId.toString(),
        name,
        email,
        role: "STUDENT",
        roll,
        session,
        registration,
        board,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    await connectToDatabase();
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ message: "Missing credentials" });
    const user = await usersCollection.findOne({ email });
    if (!user || !user.passwordHash || !user.passwordSalt)
      return res.status(401).json({ message: "Invalid email or password" });
    if (!verifyPassword(password, user.passwordSalt, user.passwordHash))
      return res.status(401).json({ message: "Invalid email or password" });
    if (user.isActive === false)
      return res.status(403).json({ message: "Account disabled" });
    const token = signJwt({ sub: user._id.toString(), role: user.role });
    return res.json({
      token,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/auth/me", authRequired, async (req, res) => {
  try {
    await connectToDatabase();
    const user = await usersCollection.findOne(
      { _id: new ObjectId(req.user.id) },
      { projection: { passwordHash: 0, passwordSalt: 0 } }
    );
    return res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/create-user", async (req, res) => {
  try {
    await connectToDatabase();

    const data = req.body;
    const isUserExist = await usersCollection.findOne({ email: data.email });
    if (isUserExist) {
      return res.send({ message: false, data });
    }

    const newUser = await usersCollection.insertOne(data);
    res.send({ user: newUser, success: true });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Server error" });
  }
});

app.get("/api/user/me", async (req, res) => {
  try {
    await connectToDatabase();

    const email = req.query.email;
    console.log("email...", email);

    const response = await usersCollection.findOne({ email: email });
    res.send(response);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Server error" });
  }
});

// Student feedback: create (auth optional, allows anonymous)
app.post("/api/feedback", async (req, res) => {
  try {
    await connectToDatabase();

    const data = req.body;

    // Try optional auth
    let author = null;
    try {
      const header = req.headers.authorization || "";
      const token = header.startsWith("Bearer ") ? header.slice(7) : null;
      if (token) {
        const decoded = verifyJwt(token);
        author = { id: decoded.sub };
      }
    } catch (_) {
      author = null;
    }

    const feedback = {
      time: new Date(),
      ...data,
      ...(author ? { authorId: author.id } : { anonymous: true }),
    };

    const updatedFeedback = await feedbackCollection.insertOne(feedback);
    res.send({ success: true, id: updatedFeedback.insertedId });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Server error" });
  }
});

// Student feedback: list own
app.get("/api/feedback", authRequired, async (req, res) => {
  try {
    await connectToDatabase();

    const items = await feedbackCollection
      .find({ authorId: req.user.id })
      .sort({ time: -1 })
      .toArray();
    res.send(items);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Server error" });
  }
});

// Student feedback: update own
app.patch("/api/feedback/:id", authRequired, async (req, res) => {
  try {
    await connectToDatabase();
    const { id } = req.params;
    const update = req.body || {};
    const result = await feedbackCollection.updateOne(
      { _id: new ObjectId(id), authorId: req.user.id },
      { $set: { ...update, updatedAt: new Date() } }
    );
    if (result.matchedCount === 0)
      return res.status(404).json({ message: "Not found" });
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Server error" });
  }
});

// Student feedback: delete own
app.delete("/api/feedback/:id", authRequired, async (req, res) => {
  try {
    await connectToDatabase();
    const { id } = req.params;
    const result = await feedbackCollection.deleteOne({
      _id: new ObjectId(id),
      authorId: req.user.id,
    });
    if (result.deletedCount === 0)
      return res.status(404).json({ message: "Not found" });
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Server error" });
  }
});

// Admin feedback management
app.get(
  "/api/admin/feedback",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const items = await feedbackCollection
        .find({})
        .sort({ time: -1 })
        .toArray();
      res.json(items);
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: "Server error" });
    }
  }
);

app.patch(
  "/api/admin/feedback/:id",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const { id } = req.params;
      const update = req.body || {};
      const result = await feedbackCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { ...update, updatedAt: new Date() } }
      );
      if (result.matchedCount === 0)
        return res.status(404).json({ message: "Not found" });
      res.json({ success: true });
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: "Server error" });
    }
  }
);

app.delete(
  "/api/admin/feedback/:id",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const { id } = req.params;
      const result = await feedbackCollection.deleteOne({
        _id: new ObjectId(id),
      });
      if (result.deletedCount === 0)
        return res.status(404).json({ message: "Not found" });
      res.json({ success: true });
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: "Server error" });
    }
  }
);

// QA public endpoints
app.get("/api/qa/categories", async (req, res) => {
  try {
    await connectToDatabase();
    let items = await qaCategoriesCollection
      .find({ isActive: { $ne: false } })
      .sort({ displayName: 1 })
      .toArray();
    // Fallback to legacy collection name if primary is empty
    if (!items || items.length === 0) {
      const legacy = await client
        .db("admission")
        .collection("categories")
        .find({ isActive: { $ne: false } })
        .sort({ displayName: 1 })
        .toArray();
      items = legacy;
    }
    res.json(items || []);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/qa/questions", async (req, res) => {
  try {
    await connectToDatabase();
    const { category, subcategory, q } = req.query;
    const filter = { isActive: { $ne: false } };
    if (category) filter.category = category;
    if (subcategory) filter.subcategory = subcategory;

    // Try text search if q provided; fallback to regex when no text index
    let primaryFilter = { ...filter };
    if (q) {
      primaryFilter = {
        ...filter,
        $or: [
          { question: { $regex: q, $options: "i" } },
          { answer: { $regex: q, $options: "i" } },
          { keywords: { $regex: q, $options: "i" } },
        ],
      };
    }

    let items = await qaQuestionsCollection
      .find(primaryFilter)
      .sort({ priority: 1, usageCount: -1, createdAt: -1 })
      .toArray();

    // Fallback to legacy collection name if primary is empty
    if (!items || items.length === 0) {
      let legacyFilter = { ...filter };
      if (q) {
        legacyFilter = {
          ...filter,
          $or: [
            { question: { $regex: q, $options: "i" } },
            { answer: { $regex: q, $options: "i" } },
            { keywords: { $regex: q, $options: "i" } },
          ],
        };
      }
      const legacy = await client
        .db("admission")
        .collection("qa_pairs")
        .find(legacyFilter)
        .sort({ priority: 1, usageCount: -1, createdAt: -1 })
        .toArray();
      items = legacy;
    }

    res.json(items || []);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Student QA: categories with question counts
app.get("/api/student/qa/categories", async (req, res) => {
  try {
    await connectToDatabase();

    // Get categories
    let categories = await qaCategoriesCollection
      .find({ isActive: { $ne: false } })
      .sort({ displayName: 1 })
      .toArray();

    // Fallback to legacy collection
    if (!categories || categories.length === 0) {
      categories = await client
        .db("admission")
        .collection("categories")
        .find({ isActive: { $ne: false } })
        .sort({ displayName: 1 })
        .toArray();
    }

    // Get question counts for each category
    const categoriesWithCounts = await Promise.all(
      categories.map(async (category) => {
        const count = await qaQuestionsCollection.countDocuments({
          category: category.name,
          isActive: { $ne: false },
        });

        // Fallback to legacy collection for count
        const legacyCount =
          count === 0
            ? await client
                .db("admission")
                .collection("qa_pairs")
                .countDocuments({
                  category: category.name,
                  isActive: { $ne: false },
                })
            : 0;

        return {
          ...category,
          questionCount: count + legacyCount,
        };
      })
    );

    res.json(categoriesWithCounts || []);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Student QA: questions by category
app.get("/api/student/qa/questions", async (req, res) => {
  try {
    await connectToDatabase();
    const { category, subcategory, q, limit = 20 } = req.query;

    if (!category) {
      return res.status(400).json({ message: "Category is required" });
    }

    const filter = {
      category,
      isActive: { $ne: false },
    };
    if (subcategory) filter.subcategory = subcategory;

    // Try text search if q provided
    let searchFilter = { ...filter };
    if (q) {
      searchFilter = {
        ...filter,
        $or: [
          { question: { $regex: q, $options: "i" } },
          { answer: { $regex: q, $options: "i" } },
          { keywords: { $regex: q, $options: "i" } },
        ],
      };
    }

    let items = await qaQuestionsCollection
      .find(searchFilter)
      .sort({ priority: 1, usageCount: -1, createdAt: -1 })
      .limit(parseInt(limit))
      .toArray();

    // Fallback to legacy collection if primary is empty
    if (!items || items.length === 0) {
      let legacyFilter = { ...filter };
      if (q) {
        legacyFilter = {
          ...filter,
          $or: [
            { question: { $regex: q, $options: "i" } },
            { answer: { $regex: q, $options: "i" } },
            { keywords: { $regex: q, $options: "i" } },
          ],
        };
      }
      items = await client
        .db("admission")
        .collection("qa_pairs")
        .find(legacyFilter)
        .sort({ priority: 1, usageCount: -1, createdAt: -1 })
        .limit(parseInt(limit))
        .toArray();
    }

    res.json(items || []);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// QA admin CRUD
app.post(
  "/api/admin/qa/categories",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const doc = {
        ...req.body,
        createdAt: new Date(),
        isActive: req.body?.isActive ?? true,
      };
      const r = await qaCategoriesCollection.insertOne(doc);
      res.json({ id: r.insertedId });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.post(
  "/api/admin/qa/questions",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const doc = {
        usageCount: 0,
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        ...req.body,
      };
      const r = await qaQuestionsCollection.insertOne(doc);
      res.json({ id: r.insertedId });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.patch(
  "/api/admin/qa/questions/:id",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const { id } = req.params;
      const r = await qaQuestionsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { ...req.body, updatedAt: new Date() } }
      );
      if (r.matchedCount === 0)
        return res.status(404).json({ message: "Not found" });
      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.delete(
  "/api/admin/qa/questions/:id",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const { id } = req.params;
      const r = await qaQuestionsCollection.deleteOne({
        _id: new ObjectId(id),
      });
      if (r.deletedCount === 0)
        return res.status(404).json({ message: "Not found" });
      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Notice board
app.get("/api/notices", async (req, res) => {
  try {
    await connectToDatabase();
    const items = await noticesCollection
      .find({ isActive: { $ne: false }, publishAt: { $lte: new Date() } })
      .sort({ publishAt: -1 })
      .toArray();
    res.json(items);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Server error" });
  }
});

// Admin: list all notices
app.get(
  "/api/admin/notices",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const items = await noticesCollection
        .find({})
        .sort({ createdAt: -1 })
        .toArray();
      res.json(items);
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.post(
  "/api/admin/notices",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const doc = {
        title: req.body?.title,
        body: req.body?.body,
        isActive: req.body?.isActive ?? true,
        publishAt: req.body?.publishAt
          ? new Date(req.body.publishAt)
          : new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const r = await noticesCollection.insertOne(doc);
      res.json({ id: r.insertedId });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.patch(
  "/api/admin/notices/:id",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const { id } = req.params;
      const r = await noticesCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { ...req.body, updatedAt: new Date() } }
      );
      if (r.matchedCount === 0)
        return res.status(404).json({ message: "Not found" });
      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.delete(
  "/api/admin/notices/:id",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const { id } = req.params;
      const r = await noticesCollection.deleteOne({ _id: new ObjectId(id) });
      if (r.deletedCount === 0)
        return res.status(404).json({ message: "Not found" });
      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Student management (admin)
app.get(
  "/api/admin/users",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const users = await usersCollection
        .find(
          {
            role: { $ne: "SUPER_ADMIN" },
          },
          { projection: { passwordHash: 0, passwordSalt: 0 } }
        )
        .sort({ createdAt: -1 })
        .toArray();
      res.json(users);
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.patch(
  "/api/admin/users/:id/role",
  authRequired,
  requireRole("SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const { id } = req.params;
      const { role } = req.body || {};
      if (!role) return res.status(400).json({ message: "Role required" });
      const r = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { role } }
      );
      if (r.matchedCount === 0)
        return res.status(404).json({ message: "Not found" });
      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.patch(
  "/api/admin/users/:id/status",
  authRequired,
  requireRole("ADMIN", "SUPER_ADMIN"),
  async (req, res) => {
    try {
      await connectToDatabase();
      const { id } = req.params;
      const { isActive } = req.body || {};
      const r = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { isActive: !!isActive } }
      );
      if (r.matchedCount === 0)
        return res.status(404).json({ message: "Not found" });
      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.post("/api/ask-ai", async (req, res) => {
  try {
    const data = req.body;
    const prompt = data?.finalPrompt;

    if (!prompt || !prompt.trim()) {
      return res.status(400).json({ error: "Prompt is required" });
    }

    const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: prompt,
    });

    res.send({
      success: true,
      response: response?.text,
    });
  } catch (error) {
    console.error("AI Error:", error);
    res.status(500).json({
      success: false,
      error: "Something went wrong with Gemini API",
    });
  }
});

// Health endpoint
app.get("/api", async (req, res) => {
  try {
    const started = Date.now();
    let dbConnectedFlag = false;
    try {
      await connectToDatabase();
      dbConnectedFlag = true;
    } catch (_) {
      dbConnectedFlag = false;
    }
    res.json({
      ok: true,
      name: "farabis-admission-help-desk-server",
      version: "1.0.0",
      uptimeMs: process.uptime() * 1000,
      responseTimeMs: Date.now() - started,
      dbConnected: dbConnectedFlag,
    });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Not Found", path: req.originalUrl });
});

// Error handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err);
  const status = err?.status || 500;
  res.status(status).json({
    message: status === 500 ? "Internal Server Error" : err.message,
  });
});

export default app;
