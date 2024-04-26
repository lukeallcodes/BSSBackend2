import express from "express";
import { collections } from "../database";
import { ObjectId } from "mongodb";
export const userRouter = express.Router();

// Get all users
userRouter.get("/", async (req, res) => {
  if(collections.users){
    try {
      const users = await collections.users.find().toArray();
      res.json(users);
    } catch (error: any) { // Handle 'unknown' type error
      console.error("Error fetching users:", error);
      res.status(500).send("Internal Server Error");
    }
  }
});

// Update a user
userRouter.put('/update', async (req, res) => {
  if(collections.clients){
    try {
      const { _id, ...updatedUser } = req.body;

      if (!ObjectId.isValid(_id)) {
        return res.status(400).send("Invalid user ID");
      }

      const updateResult = await collections.users.updateOne(
        { _id: new ObjectId(_id) },
        { $set: updatedUser }
      );

      if (updateResult.modifiedCount === 1) {
        res.status(200).json({ message: "User updated successfully" });
      } else {
        res.status(404).json({ message: "User not found or no changes made" });
      }
    } catch (err: any) { // Handle 'unknown' type error
      console.error("Error updating user:", err);
      res.status(500).json({ message: "Internal server error" });
    }
  }
});

// Get a single user by ID
userRouter.get("/:userId", async (req, res) => {
  if(collections.clients){
    try {
      const userId = req.params.userId;

      if (!ObjectId.isValid(userId)) {
        return res.status(400).send("Invalid user ID");
      }

      const user = await collections.users.findOne({ _id: new ObjectId(userId) });

      if (user) {
        res.json(user);
      } else {
        res.status(404).send("User not found");
      }
    } catch (error: any) { // Handle 'unknown' type error
      console.error("Error fetching user by ID:", error);
      res.status(500).send("Internal Server Error");
    }
  }
});
