import express from "express";
import { verifyToken } from "../middleware/auth.js";
import bcrypt from "bcryptjs";
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

router.post("/create-user", verifyToken, (req, res) => { 
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied" });
  }

  const { name, email, password, phone_number, role_id } = req.body;

  if (!name || !email || !password || !role_id) {
    return res.status(400).json({ error: "Name, email, password, and role_id are required" });
  }

  const hashed = bcrypt.hashSync(password, 10);
 
  db.query(
    "INSERT INTO users (name, email, password, phone_number) VALUES (?, ?, ?, ?)",
    [name, email, hashed, phone_number],
    (err, result) => {
      if (err) return res.status(500).json({ error: err });

      const userId = result.insertId; 
 
      db.query(
        "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
        [userId, role_id],
        (err2) => {
          if (err2) return res.status(500).json({ error: err2 });

          res.json({ message: "User created successfully", userId, role_id });
        }
      );
    }
  );
});


 router.put("/update-user/:id", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied" });
  }

  const userId = req.params.id;
  const { name, email, phone_number, role_id } = req.body;

  if (!name || !email || !role_id) {
    return res.status(400).json({ error: "Name, email, and role_id are required" });
  }

  db.query(
    "UPDATE users SET name = ?, email = ?, phone_number = ? WHERE id = ?",
    [name, email, phone_number, userId],
    (err, result) => {
      if (err) return res.status(500).json({ error: err });
      db.query(
        "UPDATE user_roles SET role_id = ? WHERE user_id = ?",
        [role_id, userId],
        (err2) => {
          if (err2) return res.status(500).json({ error: err2 });

          res.json({ message: "User updated successfully", userId, role_id });
        }
      );
    }
  );
});




export default router;
