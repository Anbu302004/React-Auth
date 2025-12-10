import express from "express";
import { verifyToken } from "../middleware/auth.js";
import bcrypt from "bcryptjs";
import db from "../config/db.js";

const router = express.Router();

// ========================= Validation Function =========================
function validateUserInput({ name, email, password, phone_number, role_id }, isUpdate = false) {
  const errors = [];

  // Trim all fields
  name = name?.trim();
  email = email?.trim();
  password = password?.trim();
  phone_number = phone_number?.trim();
  role_id = role_id?.toString().trim();

  // Required fields
  if (!name) errors.push("Name is required");
  if (!email) errors.push("Email is required");
  if (!phone_number) errors.push("Phone number is required");
  if (!isUpdate && !password) errors.push("Password is required"); // password optional for update
  if (!role_id) errors.push("Role ID is required");

  // Name validation
  if (name && (name.length < 3 || name.length > 50))
    errors.push("Name must be between 3 and 50 characters");
  if (name && !/^[A-Za-z\s]+$/.test(name))
    errors.push("Name can only contain letters and spaces");

  // Email validation
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    errors.push("Invalid email format");

  // Phone number validation
  if (phone_number && !/^[0-9]{10}$/.test(phone_number))
    errors.push("Phone number must be 10 digits");

  // Password validation
  if (password && password.length < 6)
    errors.push("Password must be at least 6 characters long");

  return { errors, name, email, password, phone_number, role_id };
}

// ========================= List Users =========================
router.get("/users", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ status: false, messages: ["Access denied"], data: [] });
  }

  let sql = "SELECT * FROM users u LEFT JOIN user_roles ur ON u.id = ur.user_id LEFT JOIN roles r ON ur.role_id = r.id";
  const params = [];

  // Filter by role_id if query param exists
  if (req.query.role_id) {
    sql += " WHERE r.id = ?";
    params.push(req.query.role_id);
  }

  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).json({ status: false, messages: ["Database error"], data: [] });
    return res.json({ status: true, messages: ["Users fetched successfully"], data: results });
  });
});

// ========================= Create User =========================
router.post("/create", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ status: false, messages: ["Access denied"], data: [] });
  }

  const { errors, name, email, password, phone_number, role_id } = validateUserInput(req.body);

  if (errors.length > 0) return res.status(400).json({ status: false, messages: errors, data: [] });

  // Check uniqueness of email and phone
  db.query("SELECT id, email, phone_number FROM users WHERE email = ? OR phone_number = ?", [email, phone_number], (err, existingUsers) => {
    if (err) return res.status(500).json({ status: false, messages: ["Database error"], data: [] });

    existingUsers.forEach(u => {
      if (u.email === email) errors.push("Email already exists");
      if (u.phone_number === phone_number) errors.push("Phone number already exists");
    });
    if (errors.length > 0) return res.status(400).json({ status: false, messages: [...new Set(errors)], data: [] });

    const hashedPassword = bcrypt.hashSync(password, 10);

    db.query("INSERT INTO users (name, email, password, phone_number, status, email_verify) VALUES (?, ?, ?, ?, 'active', 0)", [name, email, hashedPassword, phone_number], (err, result) => {
      if (err) return res.status(500).json({ status: false, messages: ["Database error"], data: [] });

      const userId = result.insertId;

      db.query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", [userId, role_id], (err2) => {
        if (err2) return res.status(500).json({ status: false, messages: ["Database error"], data: [] });

        db.query("SELECT name AS role FROM roles WHERE id = ?", [role_id], (err3, roleRes) => {
          if (err3) return res.status(500).json({ status: false, messages: ["Database error"], data: [] });

          return res.status(201).json({
            status: true,
            messages: ["User created successfully"],
            data: [{
              id: userId,
              name,
              email,
              phone_number,
              role_id,
              role: roleRes[0]?.role || null,
              status: "active",
              email_verify: 0
            }]
          });
        });
      });
    });
  });
});

// ========================= Update User =========================
router.put("/update/:id", verifyToken, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ status: false, messages: ["Access denied"], data: [] });

  const userId = req.params.id;
  if (req.user.id == userId) return res.status(400).json({ status: false, messages: ["Cannot update own account via this route"], data: [] });

  const { errors, name, email, password, phone_number, role_id } = validateUserInput(req.body, true);

  if (errors.length > 0) return res.status(400).json({ status: false, messages: errors, data: [] });

  db.query("SELECT id FROM users WHERE (email = ? OR phone_number = ?) AND id != ?", [email, phone_number, userId], (err, existingUsers) => {
    if (err) return res.status(500).json({ status: false, messages: ["Database error"], data: [] });
    existingUsers.forEach(u => {
      if (u.email === email) errors.push("Email already exists");
      if (u.phone_number === phone_number) errors.push("Phone number already exists");
    });
    if (errors.length > 0) return res.status(400).json({ status: false, messages: [...new Set(errors)], data: [] });

    const fieldsToUpdate = [name, email, phone_number];
    let sql = "UPDATE users SET name = ?, email = ?, phone_number = ?, email_verify = 0";
    if (password) {
      sql += ", password = ?";
      fieldsToUpdate.push(bcrypt.hashSync(password, 10));
    }
    sql += " WHERE id = ?";
    fieldsToUpdate.push(userId);

    db.query(sql, fieldsToUpdate, (err) => {
      if (err) return res.status(500).json({ status: false, messages: ["Database error"], data: [] });

      db.query("UPDATE user_roles SET role_id = ? WHERE user_id = ?", [role_id, userId], (err2) => {
        if (err2) return res.status(500).json({ status: false, messages: ["Database error"], data: [] });

        db.query("SELECT * FROM users WHERE id = ?", [userId], (err3, results) => {
          if (err3) return res.status(500).json({ status: false, messages: ["Database error"], data: [] });
          return res.json({ status: true, messages: ["User updated successfully"], data: results[0] });
        });
      });
    });
  });
});

// ========================= Delete User =========================
router.delete("/delete/:id", verifyToken, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ status: false, messages: ["Access denied"], data: [] });

  const userId = req.params.id;
  if (req.user.id == userId) return res.status(400).json({ status: false, messages: ["Cannot delete own account"], data: [] });

  db.query("DELETE FROM users WHERE id = ?", [userId], (err, result) => {
    if (err) return res.status(500).json({ status: false, messages: ["Database error"], data: [] });
    if (result.affectedRows === 0) return res.status(404).json({ status: false, messages: ["User not found"], data: [] });
    return res.json({ status: true, messages: ["User deleted successfully"], data: [{ id: userId }] });
  });
});

// ========================= Block / Unblock User =========================
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
