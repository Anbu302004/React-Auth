import express from "express";
import { verifyToken } from "../middleware/auth.js";
import db from "../config/db.js";

const router = express.Router();
 
router.get("/profile", verifyToken, (req, res) => {
  const userId = req.user.id;

  const sql = `SELECT u.id, u.name, u.email, u.phone_number FROM users u WHERE u.id =?`;

  db.query(sql, [userId], (err, results) => {
    if (err) return res.status(500).json({ error: err });

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ profile: results[0] });
  });
});

export default router;
