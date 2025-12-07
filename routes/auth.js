import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "../config/db.js";
import { verifyToken } from "../middleware/auth.js";
import dotenv from "dotenv";
dotenv.config();

const router = express.Router();
const otpStore = {};

// ========================= REGISTER =========================
router.post("/register", (req, res) => {
  const { name, email, password, phone_number } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      status: false,
      message: "Name, email and password are required"
    });
  }

  const hashed = bcrypt.hashSync(password, 10);

  db.query(
    "INSERT INTO users (name, email, password, phone_number) VALUES (?,?,?,?)",
    [name, email, hashed, phone_number],
    (err, results) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(409).json({
            status: false,
            message: "Email already registered"
          });
        }
        return res.status(500).json({ status: false, message: "Database error" });
      }

      const token = jwt.sign(
        { id: results.insertId, email, phone_number },
        process.env.JWT_SECRET
      );

      res.json({
        status: true,
        message: "User registered successfully",
        token,
        data: {
          id: results.insertId,
          name,
          email,
          phone_number
        }
      });
    }
  );
});

// ========================= LOGIN =========================
router.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) return res.status(500).json({ status: false, message: "Database error" });

    if (results.length === 0)
      return res.status(404).json({ status: false, message: "User not found" });

    const user = results[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword)
      return res.status(401).json({ status: false, message: "Invalid password" });

    db.query(
      `SELECT r.name AS role FROM roles r
       JOIN user_roles ur ON ur.role_id = r.id
       WHERE ur.user_id = ?`,
      [user.id],
      (err2, roleResults) => {
        if (err2) return res.status(500).json({ status: false, message: "Database error" });

        const role = roleResults[0]?.role || "user";
        const token = jwt.sign(
          { id: user.id, email: user.email, phone_number: user.phone_number, role },
          process.env.JWT_SECRET
        );

        res.json({
          status: true,
          message: "Login successful",
          token,
          data:{
            name: user.name,
            email: user.email,
            phone_number: user.phone_number,
            role
          }
        });
      }
    );
  });
});

// ========================= LOGIN WITH OTP =========================
router.post("/login-otp", (req, res) => {
  const { email, phone_number, otp } = req.body;

  if ((!email && !phone_number) || !otp) {
    return res.status(400).json({
      status: false,
      message: "Email or phone number and OTP are required"
    });
  }

  const key = email || phone_number;
  if (otpStore[key] != otp) {
    return res.status(401).json({ status: false, message: "Invalid OTP" });
  }

  const query = email ? "SELECT * FROM users WHERE email = ?" : "SELECT * FROM users WHERE phone_number = ?";
  const value = key;

  db.query(query, [value], (err, results) => {
    if (err) return res.status(500).json({ status: false, message: "Database error" });

    if (results.length === 0)
      return res.status(404).json({ status: false, message: "User not found" });

    const user = results[0];
    const verifyField = email ? "email_verify" : "phone_verify";

    db.query(`UPDATE users SET ${verifyField} = 1 WHERE id = ?`, [user.id]);

    db.query(
      `SELECT r.name AS role FROM roles r
       JOIN user_roles ur ON ur.role_id = r.id
       WHERE ur.user_id = ?`,
      [user.id],
      (err2, roleResults) => {
        if (err2) return res.status(500).json({ status: false, message: "Database error" });

        const role = roleResults[0]?.role || "user";
        const token = jwt.sign(
          { id: user.id, email: user.email, phone_number: user.phone_number, role },
          process.env.JWT_SECRET
        );

        delete otpStore[key];

        res.json({
          status: true,
          message: "OTP Login successful",
          token,
          data:{
            name: user.name,
            email: user.email,
            phone_number: user.phone_number,
            role
          }
        });
      }
    );
  });
});

// ========================= GENERATE OTP =========================
router.post("/generate-otp", (req, res) => {
  const { email, phone_number } = req.body;

  if (!email && !phone_number) {
    return res.status(400).json({
      status: false,
      message: "Email or phone number is required"
    });
  }

  const query = email ? "SELECT * FROM users WHERE email = ?" : "SELECT * FROM users WHERE phone_number = ?";
  const value = email || phone_number;

  db.query(query, [value], (err, results) => {
    if (err) return res.status(500).json({ status: false, message: "Database error" });

    if (results.length === 0)
      return res.status(404).json({ status: false, message: "User not found" });

    const otp = Math.floor(100000 + Math.random() * 900000);
    otpStore[value] = otp;

    res.json({
      status: true,
      message: "OTP generated successfully",
      otp    
    });
  });
});

// ========================= UPDATE PROFILE =========================
router.put("/update-profile", verifyToken, (req, res) => {
  const userId = req.user.id;
  const { name, phone_number, email, password } = req.body;

  if (!name || !phone_number || !email || !password) {
    return res.status(400).json({
      status: false,
      message: "All fields Name, phone_number, email, password are required"
    });
  }
  const updates = [];
  const values = [];

  if (name) {
    updates.push("name = ?");
    values.push(name);
  }
  if (phone_number) {
    updates.push("phone_number = ?");
    values.push(phone_number);
  }
  if (email) {
    updates.push("email = ?");
    values.push(email);
  }
  if (password) {
    const hashed = bcrypt.hashSync(password, 10);
    updates.push("password = ?");
    values.push(hashed);
  }

  if (updates.length === 0) {
    return res.status(400).json({
      status: false,
      message: "No fields to update"
    });
  }

  values.push(userId);
  const sql = `UPDATE users SET ${updates.join(", ")} WHERE id = ?`;

  db.query(sql, values, (err) => {
    if (err) {
      return res.status(500).json({
        status: false,
        message: "Database error",
        error: err
      });
    }

    db.query(
      `SELECT u.id, u.name, u.email, u.phone_number,
              r.name AS role
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
       WHERE u.id = ?`,
      [userId],
      (err2, results) => {
        if (err2 || results.length === 0) {
          return res.status(404).json({
            status: false,
            message: "User not found"
          });
        }

        res.json({
          status: true,
          message: "Profile updated successfully",
          data: results[0]
        });
      }
    );
  });
});


// ========================= LOGOUT =========================
router.post("/logout", verifyToken, (req, res) => {
  res.json({ status: true, message: "Logout successful" });
});

// ========================= ME =========================
router.get("/me", verifyToken, (req, res) => {
  const userId = req.user.id;

  db.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
    if (err) return res.status(500).json({ status: false, message: "Database error" });

    if (results.length === 0)
      return res.status(404).json({ status: false, message: "User not found" });

    res.json({
      status: true,
      message: "Profile fetched successfully",
      data: results[0]
    });
  });
});

export default router;
