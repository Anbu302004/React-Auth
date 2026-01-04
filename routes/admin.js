import express from "express";
import { verifyToken } from "../middleware/auth.js";
import bcrypt from "bcryptjs";
import db from "../config/db.js";

const router = express.Router();

/* ========================================================
   LIST USERS
======================================================== */
router.get("/users", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ status: false, message: "Access denied Authroization Required" });
    }

    // Pagination params
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    let baseSql = `
      FROM users u
      LEFT JOIN user_roles ur ON ur.user_id = u.id
      LEFT JOIN roles r ON r.id = ur.role_id
    `;

    const conditions = [];
    const params = [];

    if (req.query.role_id) {
      conditions.push("ur.role_id = ?");
      params.push(req.query.role_id);
    }

    if (req.query.status) {
      conditions.push("u.status = ?");
      params.push(req.query.status);
    }

    if (conditions.length > 0) baseSql += " WHERE " + conditions.join(" AND ");

    // Count total users
    const [countResult] = await db.query(`SELECT COUNT(*) AS total ${baseSql}`, params);
    const totalItems = countResult[0].total;
    const totalPages = Math.ceil(totalItems / limit);

    // Fetch paginated users
    const dataSql = `
      SELECT u.status, u.id, u.name, u.email, u.phone_number,
             ur.role_id, r.name AS role
      ${baseSql}
      LIMIT ? OFFSET ?
    `;

    const finalParams = [...params, limit, offset];
    const [results] = await db.query(dataSql, finalParams);

    return res.json({
      status: true,
      message: "Users fetched successfully",
      pagination: { page, limit, totalItems, totalPages },
      data: results
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: false, message: "Database error", error: err.message });
  }
});

/* ========================================================
   CREATE USER
======================================================== */
router.post("/create", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ status: false, messages: ["Access denied Authroization Required"] });
    }

    const { name, email, password, phone_number, role_id, status } = req.body;
    const errors = [];

    if (!name || name.trim().length < 3 || name.trim().length > 50)
      errors.push("Name must be between 3 and 50 characters");
    if (name && !/^[A-Za-z\s]+$/.test(name)) errors.push("Name can only contain letters and spaces");

    if (!email) errors.push("Email is required");
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push("Invalid email format");

    if (!password) errors.push("Password is required");
    if (password && password.length < 6) errors.push("Password must be at least 6 characters long");

    if (!phone_number) errors.push("Phone number is required");
    if (phone_number && !/^[0-9]{10}$/.test(phone_number)) errors.push("Phone number must be 10 digits");

    if (!role_id) errors.push("Role ID is required");
    if (status === undefined) errors.push("Status is required");

    const finalStatus = parseInt(status);
    if (![0, 1, 2].includes(finalStatus)) errors.push("Status must be 0 (blocked), 1 (active), or 2 (inactive)");

    if (errors.length > 0) return res.status(400).json({ status: false, messages: errors });

    // Check duplicates
    const [existing] = await db.query(
      "SELECT id, email, phone_number FROM users WHERE email = ? OR phone_number = ?",
      [email, phone_number]
    );

    const duplicateErrors = [];
    existing.forEach(u => {
      if (u.email === email) duplicateErrors.push("Email already exists");
      if (u.phone_number === phone_number) duplicateErrors.push("Phone number already exists");
    });
    if (duplicateErrors.length > 0) return res.status(400).json({ status: false, messages: [...new Set(duplicateErrors)] });

    const hashed = bcrypt.hashSync(password, 10);

    // Insert user
    const [insertResult] = await db.query(
      "INSERT INTO users (name, email, password, phone_number, status) VALUES (?, ?, ?, ?, ?)",
      [name, email, hashed, phone_number, finalStatus]
    );

    const userId = insertResult.insertId;

    // Assign role
    await db.query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", [userId, role_id]);

    // Get role name
    const [roleRes] = await db.query("SELECT name AS role FROM roles WHERE id = ?", [role_id]);
    const roleName = roleRes?.[0]?.role || null;

    return res.status(201).json({
      status: true,
      message: "User created successfully",
      data: { id: userId, name, email, phone_number, role_id, role: roleName, status: finalStatus }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: false, messages: ["Database error"], error: err.message });
  }
});

/* ========================================================
   UPDATE USER
======================================================== */
router.put("/update/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ status: false, message: "Access denied Authroization Required" });

    const userId = req.params.id;
    const { name, email, phone_number, password, role_id, status } = req.body;
    const errors = [];

    if (!name || name.trim().length < 3 || name.trim().length > 50)
      errors.push("Name must be between 3 and 50 characters");
    if (!/^[A-Za-z\s]+$/.test(name)) errors.push("Name can only contain letters and spaces");

    if (!email) errors.push("Email is required");
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push("Invalid email format");

    if (!phone_number) errors.push("Phone number is required");
    if (phone_number && !/^[0-9]{10}$/.test(phone_number)) errors.push("Phone number must be 10 digits");

    if (!role_id) errors.push("Role ID is required");

    let finalStatus = typeof status === "string" ? parseInt(status) : status;
    if (finalStatus !== undefined && ![0, 1, 2].includes(finalStatus))
      errors.push("Status must be 0 (blocked), 1 (active), or 2 (inactive)");

    if (password && password.length < 6) errors.push("Password must be at least 6 characters long");
    if (errors.length > 0) return res.status(400).json({ status: false, messages: errors });

    // Check duplicates
    const [existingUsers] = await db.query(
      "SELECT id, email, phone_number FROM users WHERE (email = ? OR phone_number = ?) AND id != ?",
      [email, phone_number, userId]
    );

    const duplicateErrors = [];
    existingUsers.forEach(u => {
      if (u.email === email) duplicateErrors.push("Email already exists");
      if (u.phone_number === phone_number) duplicateErrors.push("Phone number already exists");
    });
    if (duplicateErrors.length > 0) return res.status(400).json({ status: false, messages: [...new Set(duplicateErrors)] });

    // Build update
    const fields = [name, email, phone_number];
    let sql = "UPDATE users SET name = ?, email = ?, phone_number = ?, email_verify = 0, phone_verify = 0";

    if (password) {
      sql += ", password = ?";
      fields.push(bcrypt.hashSync(password, 10));
    }

    if (finalStatus !== undefined) {
      sql += ", status = ?";
      fields.push(finalStatus);
    }

    sql += " WHERE id = ?";
    fields.push(userId);

    await db.query(sql, fields);
    await db.query("UPDATE user_roles SET role_id = ? WHERE user_id = ?", [role_id, userId]);

    const [roleRes] = await db.query("SELECT name AS role FROM roles WHERE id = ?", [role_id]);
    const roleName = roleRes?.[0]?.role || null;

    const [userRes] = await db.query("SELECT * FROM users WHERE id = ?", [userId]);

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
        email_verify: userRes[0].email_verify,
        phone_verify: userRes[0].phone_verify
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: false, messages: ["Database error"], error: err.message });
  }
});
/* ========================================================
   USER OVERVIEW (VIEW DETAILS)
======================================================== */
router.get("/overview/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({
        status: false,
        message: "Access denied Authorization Required"
      });
    }

    const userId = req.params.id;

    const sql = `
      SELECT 
        u.id,
        u.name,
        u.email,
        u.phone_number,
        u.status,
        u.email_verify,
        u.phone_verify,
        u.created_at,
        r.id AS role_id,
        r.name AS role
      FROM users u
      LEFT JOIN user_roles ur ON ur.user_id = u.id
      LEFT JOIN roles r ON r.id = ur.role_id
      WHERE u.id = ?
    `;

    const [rows] = await db.query(sql, [userId]);

    if (rows.length === 0) {
      return res.status(404).json({
        status: false,
        message: "User not found"
      });
    }

    return res.json({
      status: true,
      message: "User overview fetched successfully",
      data: rows[0]
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      status: false,
      message: "Database error",
      error: err.message
    });
  }
});

/* ========================================================
   DELETE USER
======================================================== */
router.delete("/delete/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ status: false, message: "Access denied Authroization Required" });

    const userId = req.params.id;
    if (req.user.id == userId) return res.status(400).json({ status: false, message: "Cannot delete your own account" });

    const [result] = await db.query("DELETE FROM users WHERE id = ?", [userId]);

    if (result.affectedRows === 0) return res.status(404).json({ status: false, message: "User not found" });

    return res.json({ status: true, message: "User deleted successfully", user: { userId } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: false, messages: ["Database error"], error: err.message });
  }
});

/* ========================================================
   BLOCK / UNBLOCK USER
======================================================== */
router.put("/block/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ status: false, messages: ["Access denied Authroization Required"] });

    const userId = req.params.id;
    if (req.user.id == userId) return res.status(400).json({ status: false, messages: ["Cannot block own account"] });

    const { block } = req.body;
    if (typeof block !== "boolean") return res.status(400).json({ status: false, messages: ["`block` must be true or false"] });

    const [result] = await db.query("UPDATE users SET status = ? WHERE id = ?", [block ? 0 : 1, userId]);

    return res.json({
      status: true,
      messages: [`User ${block ? "blocked" : "unblocked"} successfully`],
      data: [{ id: userId, status: block ? 0 : 1 }]
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: false, messages: ["Database error"], error: err.message });
  }
});

export default router;
