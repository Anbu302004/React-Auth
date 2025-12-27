import express from "express";
import db from "../config/db.js";
import { verifyToken } from "../middleware/auth.js";

const router = express.Router();
 
router.get("/gallery", verifyToken, (req, res) => {
  db.query("SELECT * FROM gallery", (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ gallery: results });
  });
});
 
export default router;