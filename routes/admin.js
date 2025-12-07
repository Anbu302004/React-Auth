import express from "express";
import { verifyToken } from "../middleware/auth.js";
import bcrypt from "bcryptjs";
import db from "../config/db.js";
const router = express.Router();

/* =========================================
   LIST USERS (ADMIN ONLY)
========================================= */
router.get("/list-users", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ status: false, message: "Access denied" });
  }

  const sql = `
    SELECT u.id, u.name, u.email, u.phone_number, r.name AS role
    FROM users u
    LEFT JOIN user_roles ur ON ur.user_id = u.id
    LEFT JOIN roles r ON r.id = ur.role_id
  `;

  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ status: false, message: "Database error", error: err.message });
    }
    return res.json({ status: true, message: "Users fetched successfully", data: results });
  });
});


/* =========================================
   CREATE USER (ADMIN ONLY)
========================================= */
router.post("/create-user", verifyToken, (req, res) => { 
  if (req.user.role !== "admin") {
    return res.status(403).json({ status: false, message: "Access denied" });
  }

  const { name, email, password, phone_number, role_id } = req.body;

  if (!name || !email || !password || !role_id) {
    return res.status(400).json({ status: false, message: "Name, email, password, and role_id are required" });
  }

  const hashed = bcrypt.hashSync(password, 10);

  db.query(
    "INSERT INTO users (name, email, password, phone_number) VALUES (?, ?, ?, ?)",
    [name, email, hashed, phone_number],
    (err, result) => {
      if (err) { 
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(409).json({ status: false, message: "Email already exists" });
        }
        return res.status(500).json({ status: false, message: "Database error", error: err.message });
      }

      const userId = result.insertId;

      db.query(
        "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
        [userId, role_id],
        (err2) => {
          if (err2) {
            return res.status(500).json({ status: false, message: "Database error", error: err2.message });
          }

          return res.status(201).json({
            status: true,
            message: "User created successfully",
            data: { name, email, phone_number, role_id }
          });
        }
      );
    }
  );
});


/* =========================================
   UPDATE USER (ADMIN ONLY)
========================================= */
router.put("/update-user/:id", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ status: false, message: "Access denied" });
  }

  const userId = req.params.id;
  const { name, email, phone_number, role_id } = req.body;

  if (!name || !email || !role_id || !phone_number) {
    return res.status(400).json({ status: false, message: "Name, email, and role_id are required" });
  }

  db.query(
    "UPDATE users SET name = ?, email = ?, phone_number = ? WHERE id = ?",
    [name, email, phone_number, userId],
    (err, result) => {
      if (err) { 
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(409).json({ status: false, message: "Email already exists" });
        }
        return res.status(500).json({ status: false, message: "Database error", error: err.message });
      }

      db.query(
        "UPDATE user_roles SET role_id = ? WHERE user_id = ?",
        [role_id, userId],
        (err2) => {
          if (err2) {
            return res.status(500).json({ status: false, message: "Database error", error: err2.message });
          }

          return res.json({
            status: true,
            message: "User updated successfully",
             data: { userId, name, email, phone_number, role_id }
          });
        }
      );
    }
  );
});


/* =========================================
   DELETE USER (ADMIN ONLY)
========================================= */
router.delete("/delete-user/:id", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ status: false, message: "Access denied" });
  }

  const userId = req.params.id;

  db.query("DELETE FROM users WHERE id = ?", [userId], (err, result) => {
    if (err) {
      return res.status(500).json({ status: false, message: "Database error", error: err.message });
    }
 
    if (result.affectedRows === 0) {
      return res.status(404).json({ status: false, message: "User not found" });
    }

    return res.json({ status: true, message: "User deleted successfully", data: { userId } });
  });
});


export default router;
