import mongoose from "mongoose";

const recipeSchema = mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  ingredients: [
    {
      type: String,
      required: false,
    },
  ],
  instructions: {
    type: String,
    required: false,
  },

  imageUrl: {
    type: String,
    required: false,
  },
  cookingTime: {
    type: Number,
    required: false,
  },
  userOwner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
});

export const RecipesModel = mongoose.model("Recipes", recipeSchema);