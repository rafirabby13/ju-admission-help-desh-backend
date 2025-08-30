import express from 'express'
const app = express()
import { MongoClient, ObjectId, ServerApiVersion } from 'mongodb';
import dotenv from "dotenv"
import cors from "cors"
import { GoogleGenerativeAI } from "@google/generative-ai";
import { GoogleGenAI } from '@google/genai';


const port = 5000
dotenv.config()


app.use(express.json())
app.use(cors({
    origin: [
        'http://localhost:5173',     // Without slash
        'http://localhost:5173/',    // With slash (both variants)
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

        app.post("/create-user", async (req, res) => {
            const data = req.body
            const isUSerExist = await usersCollection.findOne({ email: data.email })
            if (isUSerExist) {
                // console.log(data)
                return res.send({ message: false, data })
            }

            const newUser = await usersCollection.insertOne(data)

            res.send({ user: newUser, success: true })
        })

        app.get("/user/me", async (req, res) => {
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

        app.post("/feedback", async (req, res) => {
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
        app.get('/feedback', async (req, res) => {

            try {
                const assignments = await feedbackCollection.find({}).toArray()
                console.log(assignments)
                res.send(assignments)

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server error" });
            }
        })




        /// admin q&a section 



        // ================================
        // DATABASE STRUCTURE & BACKEND API
        // ================================

        // 1. Database Collections Structure

        // 2. Categories Collection Schema
        const categorySchema = {
            _id: ObjectId,
            name: "admissionRequirements",           // Technical name for code
            displayName: "Admission Requirements",   // Display name for admin
            description: "Questions about admission requirements and eligibility",
            subcategories: [
                {
                    name: "general",
                    displayName: "General Requirements",
                    description: "Basic admission requirements"
                },
                {
                    name: "gpaRequirements",
                    displayName: "GPA Requirements",
                    description: "Grade point average related questions"
                }
            ],
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // 3. Q&A Pairs Collection Schema  
        const qaPairSchema = {
            _id: ObjectId,
            question: "What are the general admission requirements for JU undergraduate programs?",
            answer: "To apply for undergraduate programs at JU, you must have successfully completed your Higher Secondary Certificate (HSC) or equivalent exams. Your GPA should meet the minimum requirement set by the specific faculty.",
            category: "admissionRequirements",           // Links to category
            subcategory: "general",                     // Optional subcategory
            keywords: ["admission", "requirements", "undergraduate", "HSC", "GPA"], // For better matching
            priority: 1,                               // Higher priority = shown first
            isActive: true,                            // Admin can disable without deleting
            createdBy: ObjectId,                       // Admin who created it
            createdAt: new Date(),
            updatedAt: new Date(),
            usageCount: 0,                             // Track how often it's matched
            lastUsed: null                             // When it was last matched
        };

        // ================================
        // BACKEND API ENDPOINTS
        // ================================

        // Seed default categories


        // ================================
        // API ENDPOINTS FOR ADMIN
        // ================================

        // Get all categories for dropdown
        app.get("/admin/categories", async (req, res) => {
            try {


                const categories = await categoriesCollection.find({}).toArray();
                res.send({ success: true, categories });
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server error" });
            }
        });

        // Get all Q&A pairs with pagination
        app.get("/admin/qa-pairs", async (req, res) => {
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
        app.post("/admin/qa-pairs", async (req, res) => {
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
        app.put("/admin/qa-pairs/:id", async (req, res) => {
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
        app.delete("/admin/qa-pairs/:id", async (req, res) => {
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

        // ================================
        // API FOR CHATBOT TO GET Q&A
        // ================================


        // ================================
        // ADMIN MODAL FORM FIELDS
        // ================================

        /* 
        Frontend Admin Modal should include these fields:
        
        1. Question* (required)
           - Type: Textarea
           - Placeholder: "Enter the question users might ask"
           - Validation: Required, min 10 characters
        
        2. Answer* (required)  
           - Type: Textarea with rich text editor
           - Placeholder: "Provide detailed answer"
           - Validation: Required, min 20 characters
        
        3. Category* (required)
           - Type: Dropdown/Select
           - Options: Fetch from /admin/categories API
           - Validation: Required
        
        4. Subcategory (optional)
           - Type: Dropdown/Select  
           - Options: Populate based on selected category
           - Validation: Optional
        
        5. Keywords (optional)
           - Type: Tag input (allow multiple)
           - Placeholder: "admission, requirements, GPA"
           - Help text: "Add keywords to improve matching"
        
        6. Priority (optional)
           - Type: Number input
           - Default: 1
           - Range: 1-10 (10 = highest priority)
           - Help text: "Higher priority answers appear first"
        
        7. Status (optional)
           - Type: Toggle/Switch
           - Default: Active
           - Options: Active/Inactive
        
        8. Preview Button
           - Shows how the Q&A will appear in chatbot
        
        Modal Actions:
        - Save & Add Another
        - Save & Close  
        - Cancel
        */

        app.post("/ask-ai", async (req, res) => {
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
