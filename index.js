import express from 'express'

const app = express()
import { MongoClient, ObjectId, ServerApiVersion } from 'mongodb';
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

async function run() {
    try {

        const feedbackCollection = client.db("admission").collection("feedback");
        const usersCollection = client.db("admission").collection("users");
        const qaCollection = client.db("admission").collection("qa_pairs");
        const categoriesCollection = client.db("admission").collection("categories");

        app.post("/jwt", async (req, res) => {
            const user = req.body
            console.log("auth controller ", user)
            const token = jwt.sign(user, process.env.JWT_SECRET, {
                expiresIn: "30d"
            })

            console.log(token)

            res
                .cookie("token", token, {
                    httpOnly: true,
                    secure: false
                })
                .send({ success: true })
        })

        app.post("/logout", (req, res) => {
            res.clearCookie("token", {
                httpOnly: true,
                secure: false
            })
                .send({ success: true })
        })

        app.post("/api/create-user", async (req, res) => {
            const data = req.body
            const isUSerExist = await usersCollection.findOne({ email: data.email })
            if (isUSerExist) {
                // console.log(data)
                return res.send({ message: false, data })
            }

            const newUser = await usersCollection.insertOne(data)

            res.send({ user: newUser, success: true })
        })

        app.get("/api/user/me", async (req, res) => {
            const email = req.query.email
            console.log("email...", email)

            // if (req.user.email !== email) {
            //     return res.status(403).send({
            //         message: "forbidded access"
            //     })
            // }

            const response = await usersCollection.findOne({ email: email })
            res.send(response)
        })


        async function seedSuperAdmin() {
            const existingAdmin = await usersCollection.findOne({ role: "SUPER_ADMIN" });
            if (existingAdmin) {
                console.log("Admin exist")
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
        await seedSuperAdmin();

        app.post("/api/feedback", async (req, res) => {
            try {
                const data = req.body;

                console.log(data)

                // if (!data.message || data.message.trim() === "") {
                //     return res.status(400).send({ message: "Message is required" });
                // }

                // // Build feedback object
                const feedback = {
                    time: new Date(), // simple unique ID; you can use UUID
                    ...data
                }
                // // console.log(post)


                const updatedfedddback = await feedbackCollection.insertOne(feedback);
                res.send({ success: true, updatedfedddback });
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server error" });
            }
        });
        app.get('/api/feedback', async (req, res) => {

            try {
                const assignments = await feedbackCollection.find({}).toArray()
                console.log(assignments)
                res.send(assignments)

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server error" });
            }
        })


        app.get("/api/admin/categories", async (req, res) => {
            try {


                const categories = await categoriesCollection.find({}).toArray();
                res.send({ success: true, categories });
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server error" });
            }
        });

        // Get all Q&A pairs with pagination
        app.get("/api/admin/qa-pairs", async (req, res) => {
            try {

                const qaPairs = await qaCollection.find({}).toArray();

                res.send({
                    success: true,
                    qaPairs
                });
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server error" });
            }
        });
        // app.get("/admin/qa-pairs", authenticateToken, async (req, res) => {
        //     try {


        //         const page = parseInt(req.query.page) || 1;
        //         const limit = parseInt(req.query.limit) || 10;
        //         const category = req.query.category;
        //         const search = req.query.search;

        //         let query = {};

        //         if (category) {
        //             query.category = category;
        //         }

        //         if (search) {
        //             query.$or = [
        //                 { question: { $regex: search, $options: 'i' } },
        //                 { answer: { $regex: search, $options: 'i' } },
        //                 { keywords: { $in: [new RegExp(search, 'i')] } }
        //             ];
        //         }

        //         const total = await qaCollection.countDocuments(query);
        //         const qaPairs = await qaCollection
        //             .find(query)
        //             .sort({ priority: -1, createdAt: -1 })
        //             .skip((page - 1) * limit)
        //             .limit(limit)
        //             .toArray();

        //         res.send({
        //             success: true,
        //             qaPairs,
        //             pagination: {
        //                 current: page,
        //                 total: Math.ceil(total / limit),
        //                 totalItems: total
        //             }
        //         });
        //     } catch (error) {
        //         console.error(error);
        //         res.status(500).send({ message: "Server error" });
        //     }
        // });

        // Add new Q&A pair
        app.post("/api/admin/qa-pairs", async (req, res) => {
            try {
                if (req.user.role !== "ADMIN" && req.user.role !== "SUPER_ADMIN") {
                    return res.status(403).send({ message: "Access denied" });
                }

                const { question, answer, category, subcategory, keywords, priority } = req.body;

                // Basic validation
                if (!question || !answer || !category) {
                    return res.status(400).send({ message: "Question, answer, and category are required" });
                }

                // Check if category exists
                const categoryExists = await categoriesCollection.findOne({ name: category, isActive: true });
                if (!categoryExists) {
                    return res.status(400).send({ message: "Invalid category" });
                }

                const newQaPair = {
                    question: question.trim(),
                    answer: answer.trim(),
                    category,
                    subcategory: subcategory || null,
                    keywords: keywords || [],
                    priority: priority || 1,
                    isActive: true,
                    createdBy: new ObjectId(req.user.id),
                    createdAt: new Date(),
                    updatedAt: new Date(),
                    usageCount: 0,
                    lastUsed: null
                };

                const result = await qaCollection.insertOne(newQaPair);
                res.send({ success: true, qaPair: result });
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server error" });
            }
        });

        // Update Q&A pair
        app.put("/api/admin/qa-pairs/:id", async (req, res) => {
            try {
                if (req.user.role !== "ADMIN" && req.user.role !== "SUPER_ADMIN") {
                    return res.status(403).send({ message: "Access denied" });
                }

                const { id } = req.params;
                const { question, answer, category, subcategory, keywords, priority, isActive } = req.body;

                if (!question || !answer || !category) {
                    return res.status(400).send({ message: "Question, answer, and category are required" });
                }

                const updateData = {
                    question: question.trim(),
                    answer: answer.trim(),
                    category,
                    subcategory: subcategory || null,
                    keywords: keywords || [],
                    priority: priority || 1,
                    isActive: isActive !== undefined ? isActive : true,
                    updatedAt: new Date()
                };

                const result = await qaCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: updateData }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "Q&A pair not found" });
                }

                res.send({ success: true, message: "Q&A pair updated successfully" });
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server error" });
            }
        });

        // Delete Q&A pair (soft delete)
        app.delete("/api/admin/qa-pairs/:id", async (req, res) => {
            try {
                if (req.user.role !== "ADMIN" && req.user.role !== "SUPER_ADMIN") {
                    return res.status(403).send({ message: "Access denied" });
                }

                const { id } = req.params;

                const result = await qaCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { isActive: false, updatedAt: new Date() } }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "Q&A pair not found" });
                }

                res.send({ success: true, message: "Q&A pair deleted successfully" });
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server error" });
            }
        });

       

        app.post("/api/ask-ai", async (req, res) => {
            try {
                const data = req.body;
                // console.log("data.......", data);

                const prompt = data?.finalPrompt; // ✅ fix spelling

                if (!prompt || !prompt.trim()) {
                    return res.status(400).json({ error: "Prompt is required" });
                }

                // console.log("process.env.GEMINI_API_KEY:", process.env.GEMINI_API_KEY);
                const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });


                const response = await ai.models.generateContent({
                    model: "gemini-2.5-flash",
                    contents: prompt,
                });
                // console.log("response..........", response?.text)

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


        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('Welcome to My Classroom')
})

app.listen(port, () => {
    console.log(`My Classroom running at ${port}`)
})
