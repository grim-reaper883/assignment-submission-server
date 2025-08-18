const express = require("express");
const app = express();
const cookieParser = require("cookie-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const port = process.env.PORT || 5000;

//middleware
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.gvwcrqp.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server
    await client.connect();

    //collections
    const userCollection = client.db("applicationportal").collection("users");
    const assignmentCollection = client
      .db("applicationportal")
      .collection("assignments");
    const submissionCollection = client
      .db("applicationportal")
      .collection("submissions");

    //middleware
    const verifyToken = async (req, res, next) => {
      const token = req.cookies.accessToken;
      if (!token) {
        return res.status(401).json({ message: "no token provided" });
      }
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
      } catch (error) {
        return res.status(401).json({ message: "invalid token" });
      }
    };

    // Role-based middleware
    const requireRole = (roles) => {
      return (req, res, next) => {
        if (!req.user || !req.user.role) {
          return res.status(403).json({ message: "Role required" });
        }
        if (!roles.includes(req.user.role)) {
          return res.status(403).json({ message: "Insufficient permissions" });
        }
        next();
      };
    };

    // JWT
    app.post("/jwt", async (req, res) => {
      try {
        const { email } = req.body;
        const user = await userCollection.findOne({ email: email });
        if (!user) {
          return res.status(404).json({ message: "user not found" });
        }
        const token = jwt.sign(
          { email: user.email, userId: user._id, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: "1d" }
        );
        res.cookie("accessToken", token, {
          httpOnly: true,
          secure: false,
          sameSite: "lax",
          path: "/",
        });
        res.json({
          message: "login successful",
          user: { email: user.email, role: user.role, name: user.name },
        });
      } catch (error) {
        console.error("error generating jwt", error);
        res.status(500).json({ message: "internal server error" });
      }
    });

    app.post("/logout", (req, res) => {
      try {
        res.clearCookie("accessToken", {
          httpOnly: true,
          secure: false,
          sameSite: "lax",
          path: "/",
        });
        res.status(200).json({ message: "logged out successfully" });
      } catch (error) {
        console.error("Logout error:", error);
        res.status(500).json({ message: "logout failed" });
      }
    });

    //assignment api
    app.get("/assignments", async (req, res) => {
      const assignments = await assignmentCollection.find().toArray();
      res.send(assignments);
    });

    // assignment management
    app.post(
      "/assignments",
      verifyToken,
      requireRole(["instructor"]),
      async (req, res) => {
        try {
          const assignmentData = req.body;
          assignmentData.createdAt = new Date();
          assignmentData.createdBy = req.user.email;

          const result = await assignmentCollection.insertOne(assignmentData);
          res.status(201).json({
            message: "Assignment created successfully",
            assignmentId: result.insertedId,
          });
        } catch (error) {
          console.error("Error creating assignment:", error);
          res.status(500).json({ message: "internal server error" });
        }
      }
    );

    // Delete assignment
    app.delete(
      "/assignments/:id",
      verifyToken,
      requireRole(["instructor"]),
      async (req, res) => {
        try {
          const assignmentId = req.params.id;

          // Check if assignment exists
          const assignment = await assignmentCollection.findOne({
            _id: new ObjectId(assignmentId),
          });
          if (!assignment) {
            return res.status(404).json({ message: "Assignment not found" });
          }

          const result = await assignmentCollection.deleteOne({
            _id: new ObjectId(assignmentId),
          });

          if (result.deletedCount === 1) {
            res.json({ message: "Assignment deleted successfully" });
          } else {
            res.status(500).json({ message: "Failed to delete assignment" });
          }
        } catch (error) {
          console.error("Error deleting assignment:", error);
          res.status(500).json({ message: "internal server error" });
        }
      }
    );

    // Update submission  
    app.patch(
      "/submissions/:id",
      verifyToken,
      requireRole(["instructor"]),
      async (req, res) => {
        try {
          const submissionId = req.params.id;
          const { status, feedback } = req.body;

          const updateDoc = {
            $set: {
              status,
              feedback,
              reviewedAt: new Date(),
              reviewedBy: req.user.email,
            },
          };

          const result = await submissionCollection.updateOne(
            { _id: new ObjectId(submissionId) },
            updateDoc
          );

          if (result.modifiedCount === 1) {
            res.json({ message: "Submission reviewed successfully" });
          } else {
            res
              .status(404)
              .json({ message: "Submission not found or already reviewed" });
          }
        } catch (error) {
          console.error("Error reviewing submission:", error);
          res.status(500).json({ message: "Internal server error" });
        }
      }
    );

    //submission api
    app.get("/submissions", async (req, res) => {
      const submissions = await submissionCollection.find().toArray();
      res.send(submissions);
    });

    // Protected submission endpoints
    app.post(
      "/submissions",
      verifyToken,
      requireRole(["student"]),
      async (req, res) => {
        try {
          const submissionData = req.body;
          submissionData.submittedAt = new Date();
          submissionData.submittedBy = req.user.email;
          submissionData.status = "Pending"

          const result = await submissionCollection.insertOne(submissionData);
          res.status(201).json({
            message: "Submission created successfully",
            submissionId: result.insertedId,
          });
        } catch (error) {
          console.error("Error creating submission:", error);
          res.status(500).json({ message: "internal server error" });
        }
      }
    );

    //user api
    app.post("/users", async (req, res) => {
      try {
        const userData = req.body;
        //check for existing user
        const existingUser = await userCollection.findOne({
          email: userData.email,
        });
        if (existingUser) {
          return res.status(400).json({ message: "User already exists" });
        }
        // timestamp
        userData.createdAt = new Date();
        //insert user into database
        const result = await userCollection.insertOne(userData);
        res.status(201).json({
          message: "User created successfully",
          userId: result.insertedId,
        });
      } catch (error) {
        console.error("Error creating user:", error);
        res.status(500).json({ message: "internal server error" });
      }
    });

    
    app.get("/users/:email", verifyToken, async (req, res) => {
      try {
        const email = req.params.email;
        if (req.user.email !== email) {
          return res.status(403).json({ message: "Forbidden" });
        }

        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }
        res.send(user);
      } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).json({ message: "internal server error" });
      }
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("server running");
});

app.listen(port, () => {
  console.log(`server running on port ${port}`);
});
