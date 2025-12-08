import express from "express";
import { verifyToken } from "../middleware/auth.js";
import bcrypt from "bcryptjs";
import db from "../config/db.js";
const router = express.Router();

/* =========================================
   LIST USERS (ADMIN ONLY)
========================================= */
router.get("/users", verifyToken, (req, res) => {
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
router.post("/create", verifyToken, (req, res) => { 
  if (req.user.role !== "admin") {
    return res.status(403).json({ status: false, message: "Access denied" });
  }

  const { name, email, password, phone_number, role_id } = req.body;

  if (!name || !email || !password || !role_id) {
    return res.status(400).json({ status: false, message: "Name, email, password, and role_id are required" });
  }

  const hashed = bcrypt.hashSync(password, 10);

  // Insert user
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

      // Assign role
      db.query(
        "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
        [userId, role_id],
        (err2) => {
          if (err2) {
            return res.status(500).json({ status: false, message: "Database error", error: err2.message });
          }

          // Fetch role name from roles table
          db.query(
            "SELECT name AS role FROM roles WHERE id = ?",
            [role_id],
            (err3, roleRes) => {
              if (err3) {
                return res.status(500).json({ status: false, message: "Database error", error: err3.message });
              }

              const roleName = roleRes[0]?.role || null;

              return res.status(201).json({
                status: true,
                message: "User created successfully",
                data: { 
                  userId,
                  name, 
                  email, 
                  phone_number, 
                  role_id, 
                  role: roleName 
                }
              });
            }
          );
        }
      );
    }
  );
});
/* =========================================
   UPDATE USER (ADMIN ONLY)
========================================= */
 router.put("/update/:id", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ status: false, message: "Access denied" });
  }

  const userId = req.params.id;
  const { name, email, phone_number, role_id } = req.body;

  if (!name) {
    return res.status(400).json({ status: false, message: "Name is required" });
  }

  if (name.length < 3 || name.length > 50) {
    return res.status(400).json({ status: false, message: "Name must be between 3 and 50 characters" });
  }

  const nameRegex = /^[A-Za-z0-9\s]+$/;
  if (!nameRegex.test(name)) {
    return res.status(400).json({ status: false, message: "Name can only contain letters, numbers, and spaces" });
  }

  if (!phone_number) {
    return res.status(400).json({ status: false, message: "Phone number is required" });
  }

  if (phone_number.length < 10) {
    return res.status(400).json({ status: false, message: "Phone number must be at least 10 digits" });
  }

  if (!email) {
    return res.status(400).json({ status: false, message: "Email is required" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ status: false, message: "Invalid email format" });
  }

  if (!role_id) {
    return res.status(400).json({ status: false, message: "Role ID is required" });
  }

  db.query(
    "UPDATE users SET name = ?, email = ?, phone_number = ? WHERE id = ?",
    [name, email, phone_number, userId],
    (err) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(409).json({ status: false, message: "Email already exists" });
        }
        return res.status(500).json({ status: false, message: "Database error" });
      }

      db.query(
        "UPDATE user_roles SET role_id = ? WHERE user_id = ?",
        [role_id, userId],
        (err2) => {
          if (err2) {
            return res.status(500).json({ status: false, message: "Database error" });
          }

          db.query(
            "SELECT name AS role FROM roles WHERE id = ?",
            [role_id],
            (err3, roleRes) => {
              if (err3) {
                return res.status(500).json({ status: false, message: "Database error" });
              }

              const roleName = roleRes[0]?.role || null;

              return res.json({
                status: true,
                message: "User updated successfully",
                Users: { userId, name, email, phone_number, role_id, role: roleName }
              });
            }
          );
        }
      );
    }
  );
});
/* =========================================
   DELETE USER (ADMIN ONLY)
========================================= */
router.delete("/delete/:id", verifyToken, (req, res) => {
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

    return res.json({ status: true, message: "User deleted successfully", User: { userId } });
  });
});


export default router;
