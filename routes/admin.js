import express from "express";
import { verifyToken } from "../middleware/auth.js";
import db from "../config/db.js";
const router = express.Router();

router.get("/list-users", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied" });
  }

  const sql = `
    SELECT u.id, u.name, u.email, u.phone_number, r.name AS role
    FROM users u
    LEFT JOIN user_roles ur ON ur.user_id = u.id
    LEFT JOIN roles r ON r.id = ur.role_id
  `;

  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ users: results });
  });
});




export default router;
