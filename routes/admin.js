import express from "express";
import { verifyToken } from "../middleware/auth.js";
import bcrypt from "bcryptjs";
import db from "../config/db.js";
const router = express.Router();
 
// ========================= List User =========================
router.get("/users", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ status: false, message: "Access denied" });
  }

  let sql = `
    SELECT u.status, u.id, u.name, u.email, u.phone_number, ur.role_id, r.name AS role
    FROM users u
    LEFT JOIN user_roles ur ON ur.user_id = u.id
    LEFT JOIN roles r ON r.id = ur.role_id
  `;
  const params = [];

  // Check if role_id query param exists
  if (req.query.role_id) {
    sql += " WHERE ur.role_id = ?";
    params.push(req.query.role_id);
  }

  db.query(sql, params, (err, results) => {
    if (err) {
      return res.status(500).json({ status: false, message: "Database error", error: err.message });
    }
    return res.json({ status: true, message: "Users fetched successfully", data: results });
  });
});

// ========================= Create User =========================
router.post("/create", verifyToken, (req, res) => { 
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
// ========================= Update User =========================
router.put("/update/:id", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ status: false, message: "Access denied" });
  }

  const userId = req.params.id;
  const { name, email, phone_number, password, role_id, status } = req.body;

  // Basic validations
  const errors = [];

  if (!name || name.trim().length < 3 || name.trim().length > 50)
    errors.push("Name must be between 3 and 50 characters");
  if (!/^[A-Za-z\s]+$/.test(name)) errors.push("Name can only contain letters and spaces");

  if (!email) errors.push("Email is required");
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push("Invalid email format");

  if (!phone_number) errors.push("Phone number is required");
  if (phone_number && !/^[0-9]{10}$/.test(phone_number))
    errors.push("Phone number must be 10 digits");

  if (!role_id) errors.push("Role ID is required");

  if (status && !["active", "blocked"].includes(status))
    errors.push("Status must be 'active' or 'blocked'");

  if (password && password.length < 6) errors.push("Password must be at least 6 characters long");

  if (errors.length > 0) {
    return res.status(400).json({ status: false, messages: errors });
  }

  // Check duplicates for email & phone excluding current user
  db.query(
    "SELECT id, email, phone_number FROM users WHERE (email = ? OR phone_number = ?) AND id != ?",
    [email, phone_number, userId],
    (err, existingUsers) => {
      if (err) return res.status(500).json({ status: false, message: "Database error" });

      const duplicateErrors = [];
      existingUsers.forEach((u) => {
        if (u.email === email) duplicateErrors.push("Email already exists");
        if (u.phone_number === phone_number) duplicateErrors.push("Phone number already exists");
      });
      if (duplicateErrors.length > 0)
        return res.status(400).json({ status: false, messages: [...new Set(duplicateErrors)] });

      // Build update query dynamically
      const fieldsToUpdate = [name, email, phone_number];
      let sql = "UPDATE users SET name = ?, email = ?, phone_number = ?";

      if (password) {
        sql += ", password = ?";
        fieldsToUpdate.push(bcrypt.hashSync(password, 10));
      }

      if (status) {
        sql += ", status = ?";
        fieldsToUpdate.push(status);
      }

      sql += " WHERE id = ?";
      fieldsToUpdate.push(userId);

      db.query(sql, fieldsToUpdate, (err2) => {
        if (err2) return res.status(500).json({ status: false, message: "Database error" });

        // Update user role
        db.query("UPDATE user_roles SET role_id = ? WHERE user_id = ?", [role_id, userId], (err3) => {
          if (err3) return res.status(500).json({ status: false, message: "Database error" });

          // Get role name
          db.query("SELECT name AS role FROM roles WHERE id = ?", [role_id], (err4, roleRes) => {
            if (err4) return res.status(500).json({ status: false, message: "Database error" });

            const roleName = roleRes[0]?.role || null;

            // Return updated user data
            db.query("SELECT * FROM users WHERE id = ?", [userId], (err5, userRes) => {
              if (err5) return res.status(500).json({ status: false, message: "Database error" });

              return res.json({
                status: true,
                message: "User updated successfully",
                data: {
                  id: userId,
                  name: userRes[0].name,
                  email: userRes[0].email,
                  phone_number: userRes[0].phone_number,
                  role_id,
                  role: roleName,
                  status: userRes[0].status,
                },
              });
            });
          });
        });
      });
    }
  );
});

// ========================= Delete User =========================
router.delete("/delete/:id", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ status: false, message: "Access denied" });
  }

  const userId = req.params.id;
 
  if (req.user.id == userId) {
    return res.status(400).json({
      status: false,
      message: "Cannot delete your own account"
    });
  }

  db.query("DELETE FROM users WHERE id = ?", [userId], (err, result) => {
    if (err) {
      return res.status(500).json({ status: false, message: "Database error", error: err.message });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ status: false, message: "User not found" });
    }

    return res.json({ status: true, message: "User deleted successfully", user: { userId } });
  });
});

// ========================= Block User =========================
router.put("/block/:id", verifyToken, (req, res) => {
  // Only admin can block
  if (req.user.role !== "admin") {
    return res.status(403).json({
      status: false,
      messages: ["Access denied"],
      data: []
    });
  }

  const userId = req.params.id;

  // Admin cannot block themselves
  if (req.user.id == userId) {
    return res.status(400).json({
      status: false,
      messages: ["Cannot block own account"],
      data: []
    });
  }

  const { block } = req.body;

  // Validate value
  if (typeof block !== "boolean") {
    return res.status(400).json({
      status: false,
      messages: ["`block` must be true or false"],
      data: []
    });
  }

  // Update status
  db.query(
    "UPDATE users SET status = ? WHERE id = ?",
    [block ? "blocked" : "active", userId],
    (err, result) => {
      if (err) {
        return res.status(500).json({
          status: false,
          messages: ["Database error"],
          data: []
        });
      }

      return res.json({
        status: true,
        messages: [`User ${block ? "blocked" : "unblocked"} successfully`],
        data: [{ id: userId, status: block ? "blocked" : "active" }]
      });
    }
  );
});

export default router;
