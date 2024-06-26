import express from "express";
import mongoose from "mongoose";
import { RecipesModel } from "../models/Recipes.js";
import { UserModel } from "../models/Users.js";
import { verifyToken } from "./user.js";

const router = express.Router();

router.get("/", async (req, res) => {
  try {
    const result = await RecipesModel.find({});
    res.status(200).json(result);
  } catch (err) {
    res.status(500).json(err);
  }
});

// Create a new recipe
router.post("/", verifyToken, async (req, res) => {
  const recipe = new RecipesModel({
    _id: new mongoose.Types.ObjectId(),
    name: req.body.name,
    image: req.body.image,
    ingredients: req.body.ingredients,
    instructions: req.body.instructions,
    imageUrl: req.body.imageUrl,
    cookingTime: req.body.cookingTime,
    userOwner: req.body.userOwner,
  });
  console.log(recipe);

  try {
    const result = await recipe.save();
    res.status(201).json({
      createdRecipe: {
        name: result.name,
        image: result.image,
        ingredients: result.ingredients,
        instructions: result.instructions,
        _id: result._id,
      },
    });
  } catch (err) {
    // console.log(err);
    res.status(500).json(err);
  }
});

// Get a recipe by ID
router.get("/:recipeId", async (req, res) => {
  try {
    const result = await RecipesModel.findById(req.params.recipeId);
    res.status(200).json(result);
  } catch (err) {
    res.status(500).json(err);
  }
});

// Save a Recipe
router.put("/", async (req, res) => {
  const recipe = await RecipesModel.findById(req.body.recipeID);
  const user = await UserModel.findById(req.body.userID);
  try {
    user.savedRecipes.push(recipe);
    await user.save();
    res.status(201).json({ savedRecipes: user.savedRecipes });
  } catch (err) {
    res.status(500).json(err);
  }
});

router.put("/:userId/recipes/:recipeId", async (req, res) => {
  const { userId, recipeId } = req.params;

  try {
    const user = await UserModel.findById(userId);

    // Check if the user owns the recipe
    // if (!user.personalRecipes.includes(recipeId)) {
    //   return res.status(403).json({ message: "You are not authorized to edit this recipe." });
    // }

    const recipe = await RecipesModel.findByIdAndUpdate(recipeId, req.body, { new: true });

    res.status(200).json({ updatedRecipe: recipe });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Delete a saved Recipe
router.delete("/:userId/savedRecipes/:recipeId", verifyToken, async (req, res) => {
  const { userId, recipeId } = req.params;
  try {
    const user = await UserModel.findById(userId);
    user.savedRecipes.pull(recipeId);
    await user.save();
    res.status(200).json({ message: "Saved recipe removed successfully" });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Delete a recipe by ID
router.delete("/:recipeId", verifyToken, async (req, res) => {
  const { recipeId } = req.params;

  try {
    // Delete the recipe
    await RecipesModel.findByIdAndDelete(recipeId);

    res.status(200).json({ message: "Recipe deleted successfully" });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Get id of saved recipes
router.get("/savedRecipes/ids/:userId", async (req, res) => {
  try {
    const user = await UserModel.findById(req.params.userId);
    res.status(201).json({ savedRecipes: user?.savedRecipes });
  } catch (err) {
    console.log(err);
    res.status(500).json(err);
  }
});

// Get saved recipes
router.get("/savedRecipes/:userId", async (req, res) => {
  try {
    const user = await UserModel.findById(req.params.userId);
    const savedRecipes = await RecipesModel.find({
      _id: { $in: user.savedRecipes },
    });

    console.log(savedRecipes);
    res.status(201).json({ savedRecipes });
  } catch (err) {
    console.log(err);
    res.status(500).json(err);
  }
});

export { router as recipesRouter };