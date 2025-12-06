import express from "express";
import cors from "cors";
import authRoutes from "./routes/auth.js";
import categoriesRoutes from "./routes/categories.js";
import exploreRoutes from "./routes/explore.js";
import galleryRoutes from "./routes/gallery.js"; 
import pagesRoutes from "./routes/pages.js";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

app.use("/auth", authRoutes);
app.use("/api", categoriesRoutes); 
app.use("/api", exploreRoutes);
app.use("/api", galleryRoutes);
app.use("/api", pagesRoutes);

app.get("/", (req, res)=>{
    res.send("API is running...");
});

app.listen(process.env.PORT || 5000, () =>{
    console.log(`sever is ruiing on port ${process.env.PORT || 5000}`);
});