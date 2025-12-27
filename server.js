import express from "express";
import cors from "cors";
import dotenv from "dotenv";

import authRoutes from "./routes/auth.js";

dotenv.config();

const app = express();

/* ================= Middleware ================= */
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','PATCH'],
  allowedHeaders: ['Content-Type','Authorization']
}));

app.use(express.json());

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

/* ================= Health Check ================= */
app.get("/", (req, res) => {
  res.send("API is running...");
});

/* ================= Server ================= */
const PORT = Number(process.env.PORT) || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
