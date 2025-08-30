import express from 'express'
import { MongoClient, ServerApiVersion } from 'mongodb';
import dotenv from "dotenv"
import cors from "cors"
import { GoogleGenAI } from '@google/genai';

const app = express()
const port = 5000
dotenv.config()

app.use(express.json())
app.use(cors({
    origin: [
        'http://localhost:5173',     
        'http://localhost:5173/',    
        process.env.FRONTEND_URL?.replace(/\/$/, '')
    ],
    credentials: true
}))

const uri = process.env.DB_URL;
console.log(uri)

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

let feedbackCollection;
let usersCollection;
let isConnected = false;

async function connectToDatabase() {
    if (isConnected) {
        return { feedbackCollection, usersCollection };
    }

    try {
        await client.connect();
        feedbackCollection = client.db("admission").collection("feedback");
        usersCollection = client.db("admission").collection("users");
        isConnected = true;
        
        // Seed super admin
        await seedSuperAdmin();
        
        console.log("Successfully connected to MongoDB!");
        return { feedbackCollection, usersCollection };
    } catch (error) {
        console.error("Database connection error:", error);
        throw error;
    }
}

async function seedSuperAdmin() {
    try {
        const existingAdmin = await usersCollection.findOne({ role: "SUPER_ADMIN" });
        if (existingAdmin) {
            console.log("Admin exists");
            return;
        }

        const superAdmin = {
            name: "Super Admin",
            email: "farabiiit2018@gmail.com",
            phone: "01700000000",
            role: "SUPER_ADMIN",
            createdAt: new Date()
        };

        await usersCollection.insertOne(superAdmin);
        console.log("Super admin created");
    } catch (error) {
        console.error("Error seeding super admin:", error);
    }
}

// Routes
app.get('/', (req, res) => {
    res.send('Welcome to My Classroom')
})

app.post("/api/create-user", async (req, res) => {
    try {
        await connectToDatabase();
        
        const data = req.body
        const isUserExist = await usersCollection.findOne({ email: data.email })
        if (isUserExist) {
            return res.send({ message: false, data })
        }

        const newUser = await usersCollection.insertOne(data)
        res.send({ user: newUser, success: true })
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
    }
})

app.get("/api/user/me", async (req, res) => {
    try {
        await connectToDatabase();
        
        const email = req.query.email
        console.log("email...", email)

        const response = await usersCollection.findOne({ email: email })
        res.send(response)
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
    }
})

app.post("/api/feedback", async (req, res) => {
    try {
        await connectToDatabase();
        
        const data = req.body;
        console.log(data)

        const feedback = {
            time: new Date(),
            ...data
        }

        const updatedFeedback = await feedbackCollection.insertOne(feedback);
        res.send({ success: true, updatedFeedback });
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
    }
});

app.get('/api/feedback', async (req, res) => {
    try {
        await connectToDatabase();
        
        const assignments = await feedbackCollection.find({}).toArray()
        console.log(assignments)
        res.send(assignments)
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
    }
})

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
            response: response?.text
        })

    } catch (error) {
        console.error("AI Error:", error);
        res.status(500).json({
            success: false,
            error: "Something went wrong with Gemini API",
        });
    }
});

export default app;