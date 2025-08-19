import express from 'express'
const app = express()
import { MongoClient, ObjectId, ServerApiVersion } from 'mongodb';
import dotenv from "dotenv"
import cors from "cors"
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
                res.send({success: true,updatedfedddback});
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server error" });
            }
        });
        app.get('/feedback', async (req, res) => {

            try {
                const assignments = await feedbackCollection.find({}).toArray()
                console.log(assignments)
                res.send( assignments )

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server error" });
            }
        })


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
