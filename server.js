import express from "express";
import cors from "cors";
import dotenv from "dotenv";

import authRoutes from "./routes/auth.js";
import adminRoutes from "./routes/admin.js";
import usersRoutes from "./routes/users.js";
import categoriesRoutes from "./routes/categories.js";
import exploreRoutes from "./routes/explore.js";
import galleryRoutes from "./routes/gallery.js"; 
import pagesRoutes from "./routes/pages.js";

dotenv.config();

const app = express();
 
app.use(cors());
app.use(express.json()); 

 
app.use("/auth", authRoutes); 
app.use("/api", categoriesRoutes); 
app.use("/api", exploreRoutes);
app.use("/api", galleryRoutes);
app.use("/api", pagesRoutes);
app.use("/admin", adminRoutes);
app.use("/users", usersRoutes);

 
app.get("/", (req, res) => {
  res.send("API is running...");
});

const PORT = parseInt(process.env.PORT, 10) || 5000; // ensures numeric port
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
