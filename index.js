import express from 'express'

const app = express()
import { MongoClient,  ServerApiVersion } from 'mongodb';
import dotenv from "dotenv"
import cors from "cors"
import { GoogleGenAI } from '@google/genai';


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

async function initializeDatabase() {
    try {
        await client.connect();
        feedbackCollection = client.db("admission").collection("feedback");
        usersCollection = client.db("admission").collection("users");
        
        // Seed super admin
        await seedSuperAdmin();
        
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } catch (error) {
        console.error("Database connection error:", error);
    }
}
initializeDatabase();
async function seedSuperAdmin() {
    const existingAdmin = await usersCollection.findOne({ role: "SUPER_ADMIN" });
    if (existingAdmin) {
        console.log("Admin exist")
        return;
    }

    if (!existingAdmin) {
        const superAdmin = {
            name: "Super Admin",
            email: "farabiiit2018@gmail.com",
            phone: "01700000000",
            role: "SUPER_ADMIN",
            createdAt: new Date()
        };

        await usersCollection.insertOne(superAdmin);
        console.log("Super admin created");
    }
}

const ensureDBConnection = async (req, res, next) => {
    if (!feedbackCollection || !usersCollection) {
        return res.status(500).json({ error: "Database not initialized" });
    }
    next();
};

app.get('/', (req, res) => {
    res.send('Welcome to My Classroom')
})

app.post("/api/create-user", ensureDBConnection, async (req, res) => {
    try {
        const data = req.body
        const isUSerExist = await usersCollection.findOne({ email: data.email })
        if (isUSerExist) {
            return res.send({ message: false, data })
        }

        const newUser = await usersCollection.insertOne(data)
        res.send({ user: newUser, success: true })
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
    }
})
app.get("/api/user/me", ensureDBConnection, async (req, res) => {
    try {
        const email = req.query.email
        console.log("email...", email)

        const response = await usersCollection.findOne({ email: email })
        res.send(response)
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
    }
})

app.post("/api/feedback", ensureDBConnection, async (req, res) => {
    try {
        const data = req.body;
        console.log(data)

        const feedback = {
            time: new Date(),
            ...data
        }

        const updatedfedddback = await feedbackCollection.insertOne(feedback);
        res.send({ success: true, updatedfedddback });
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
    }
});

app.get('/api/feedback', ensureDBConnection, async (req, res) => {
    try {
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

// async function run() {
//     try {

//         const feedbackCollection = client.db("admission").collection("feedback");
//         const usersCollection = client.db("admission").collection("users");

      

//         app.post("/api/create-user", async (req, res) => {
//             const data = req.body
//             const isUSerExist = await usersCollection.findOne({ email: data.email })
//             if (isUSerExist) {
//                 // console.log(data)
//                 return res.send({ message: false, data })
//             }

//             const newUser = await usersCollection.insertOne(data)

//             res.send({ user: newUser, success: true })
//         })

//         app.get("/api/user/me", async (req, res) => {
//             const email = req.query.email
//             console.log("email...", email)

//             // if (req.user.email !== email) {
//             //     return res.status(403).send({
//             //         message: "forbidded access"
//             //     })
//             // }

//             const response = await usersCollection.findOne({ email: email })
//             res.send(response)
//         })


//         async function seedSuperAdmin() {
//             const existingAdmin = await usersCollection.findOne({ role: "SUPER_ADMIN" });
//             if (existingAdmin) {
//                 console.log("Admin exist")
//             }

//             if (!existingAdmin) {
//                 const superAdmin = {
//                     name: "Super Admin",
//                     email: "farabiiit2018@gmail.com",
//                     phone: "01700000000",
//                     role: "SUPER_ADMIN",
//                     createdAt: new Date()
//                 };

//                 await usersCollection.insertOne(superAdmin);
//                 console.log("Super admin created");
//             }
//         }
//         await seedSuperAdmin();

//         app.post("/api/feedback", async (req, res) => {
//             try {
//                 const data = req.body;

//                 console.log(data)

//                 // if (!data.message || data.message.trim() === "") {
//                 //     return res.status(400).send({ message: "Message is required" });
//                 // }

//                 // // Build feedback object
//                 const feedback = {
//                     time: new Date(), // simple unique ID; you can use UUID
//                     ...data
//                 }
//                 // // console.log(post)


//                 const updatedfedddback = await feedbackCollection.insertOne(feedback);
//                 res.send({ success: true, updatedfedddback });
//             } catch (error) {
//                 console.error(error);
//                 res.status(500).send({ message: "Server error" });
//             }
//         });
//         app.get('/api/feedback', async (req, res) => {

//             try {
//                 const assignments = await feedbackCollection.find({}).toArray()
//                 console.log(assignments)
//                 res.send(assignments)

//             } catch (error) {
//                 console.error(error);
//                 res.status(500).send({ message: "Server error" });
//             }
//         })



       

//         app.post("/api/ask-ai", async (req, res) => {
//             try {
//                 const data = req.body;
//                 // console.log("data.......", data);

//                 const prompt = data?.finalPrompt; // ✅ fix spelling

//                 if (!prompt || !prompt.trim()) {
//                     return res.status(400).json({ error: "Prompt is required" });
//                 }

//                 // console.log("process.env.GEMINI_API_KEY:", process.env.GEMINI_API_KEY);
//                 const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });


//                 const response = await ai.models.generateContent({
//                     model: "gemini-2.5-flash",
//                     contents: prompt,
//                 });
//                 // console.log("response..........", response?.text)

//                 res.send({
//                     success: true,
//                     response: response?.text
//                 })


//             } catch (error) {
//                 console.error("AI Error:", error);
//                 res.status(500).json({
//                     success: false,
//                     error: "Something went wrong with Gemini API",
//                 });
//             }
//         });


//         console.log("Pinged your deployment. You successfully connected to MongoDB!");
//     } finally {
//         // Ensures that the client will close when you finish/error
//         // await client.close();
//     }
// }
// run().catch(console.dir);

// app.get('/', (req, res) => {
//     res.send('Welcome to My Classroom')
// })

// app.listen(port, () => {
//     console.log(`My Classroom running at ${port}`)
// })



export default app;
