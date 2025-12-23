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

/* ================= Middleware ================= */
app.use(cors());

/* 1️⃣ JSON parser */
app.use(express.json());

/* 2️⃣ JSON syntax error handler */
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    return res.status(400).json({
      status: false,
      messages: ["Invalid JSON format. Please check commas and syntax"]
    });
  }
  next();
});

/* ================= Routes ================= */
app.use("/auth", authRoutes);
app.use("/api", categoriesRoutes);
app.use("/api", exploreRoutes);
app.use("/api", galleryRoutes);
app.use("/api", pagesRoutes);
app.use("/admin", adminRoutes);
app.use("/users", usersRoutes);

/* ================= Health Check ================= */
app.get("/", (req, res) => {
  res.send("API is running...");
});

/* ================= Server ================= */
const PORT = Number(process.env.PORT) || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
