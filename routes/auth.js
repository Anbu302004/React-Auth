import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "../config/db.js"; 
import { verifyToken, logout } from "../middleware/auth.js";
import dotenv from "dotenv";
dotenv.config();

const router = express.Router();
const otpStore = {}; 
// ========================= REGISTER =========================
router.post("/register", (req, res) => {
  const { name, email, password, phone_number } = req.body;
  if(!name) {
    return  res.status(400).json({ status: false, message: "Name is required" });
  }
  if(!email) {
    return res.status(400).json({ status: false, message: "Email is required" });
  }
  if(!password) {
    return res.status(400).json({ status: false, message: "Password is required" });
  }
  if(!phone_number || phone_number.trim() === "") {
    return res.status(400).json({ status: false, message: "Phone number is required" });
  }
  if (name.length < 3 || name.length > 50) {
    return res.status(400).json({ status: false, message: "Name must be between 3 and 50 characters" });
  }

  const nameRegex = /^[A-Za-z0-9\s]+$/;
  if (!nameRegex.test(name)) {
    return res.status(400).json({ status: false, message: "Name can only contain letters and spaces" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ status: false, message: "Invalid email format" });
  }

  if (password.length < 6) {
    return res.status(400).json({ status: false, message: "Password must be at least 6 characters long" });
  }

  const hashed = bcrypt.hashSync(password, 10);
 
  db.query(
    "INSERT INTO users (name, email, password, phone_number) VALUES (?,?,?,?)",
    [name, email, hashed, phone_number],
    (err, results) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(409).json({ status: false, message: "Email already registered" });
        }
        return res.status(500).json({ status: false, message: "Database error" });
      }

      const userId = results.insertId;
 
      db.query("SELECT id AS role_id, name AS role_name FROM roles WHERE name = 'user' LIMIT 1", (err2, roleRes) => {
        if (err2 || !roleRes.length) {
          return res.status(500).json({ status: false, message: "Default role not found" });
        }

        const roleData = roleRes[0];
 
        db.query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", [userId, roleData.role_id], (err3) => {
          if (err3) {
            return res.status(500).json({ status: false, message: "Role assignment failed" });
          } 
          const token = jwt.sign(
            { id: userId, email, phone_number, role_id: roleData.role_id, role: roleData.role_name },
            process.env.JWT_SECRET
          );

          res.json({
            status: true,
            message: "User registered successfully",
            token,
            User: {
              id: userId,
              name,
              email,
              phone_number,
              role_id: roleData.role_id,
              role: roleData.role_name
            }
          });
        });
      });
    }
  );
});  
// ========================= LOGIN =========================
router.post("/login", (req, res) => {
  const { email, password } = req.body;
 
  if (!email) {
    return res.status(400).json({ status: false, message: "Email is required" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ status: false, message: "Invalid email format" });
  }

  if (!password) {
    return res.status(400).json({ status: false, message: "Password is required" });
  }

  if (password.length < 6) {
    return res.status(400).json({ status: false, message: "Password must be at least 6 characters long" });
  }

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) return res.status(500).json({ status: false, message: "Database error" });

    if (results.length === 0)
      return res.status(401).json({ status: false, message: "Incorrect email or password" });

    const user = results[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword)
      return res.status(401).json({ status: false, message: "Incorrect email or password" });
 
    db.query(
      `SELECT r.id AS role_id, r.name AS role
       FROM roles r
       JOIN user_roles ur ON ur.role_id = r.id
       WHERE ur.user_id = ?`,
      [user.id],
      (err2, roleResults) => {
        if (err2) return res.status(500).json({ status: false, message: "Database error" });

        if (!roleResults || roleResults.length === 0) {
          return res.status(403).json({ status: false, message: "User has no assigned role" });
        }

        const { role_id, role } = roleResults[0];

        const token = jwt.sign(
          { id: user.id, email: user.email, phone_number: user.phone_number, role_id, role },
          process.env.JWT_SECRET
        );

        res.json({
          status: true,
          message: "Login successful",
          token,
          data: {
            userId: user.id,
            name: user.name,
            email: user.email,
            phone_number: user.phone_number,
            role_id,
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

  if (!email && !phone_number) {
    return res.status(400).json({ status: false, message: "Email or phone number is required" });
  }

  if (!otp) {
    return res.status(400).json({ status: false, message: "OTP is required" });
  }

  const key = email || phone_number;

  if (!otpStore[key] || otpStore[key] != otp) {
    return res.status(401).json({ status: false, message: "Invalid credentials" });
  }

  const query = email ? "SELECT * FROM users WHERE email = ?" : "SELECT * FROM users WHERE phone_number = ?";
  db.query(query, [key], (err, results) => {
    if (err) return res.status(500).json({ status: false, message: "Database error" });

    if (results.length === 0) {
      return res.status(404).json({ status: false, message: "Account not found, please register first" });
    }

    const user = results[0];
    const verifyField = email ? "email_verify" : "phone_verify";
 
    db.query(`UPDATE users SET ${verifyField} = 1 WHERE id = ?`, [user.id], (errUpdate) => {
      if (errUpdate) return res.status(500).json({ status: false, message: "Database error" });
 
      db.query(
        `SELECT r.id AS role_id, r.name AS role 
         FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = ?`,
        [user.id],
        (err2, roleResults) => {
          if (err2) return res.status(500).json({ status: false, message: "Database error" });

          if (!roleResults || roleResults.length === 0) {
            return res.status(403).json({ status: false, message: "User has no assigned role" });
          }

          const { role_id, role } = roleResults[0];

          const token = jwt.sign(
            { id: user.id, email: user.email, phone_number: user.phone_number, role_id, role },
            process.env.JWT_SECRET
          );
 
          delete otpStore[key];

          res.json({
            status: true,
            message: "Logged in successfully",
            token,
            data: {
              userId: user.id,
              name: user.name,
              email: user.email,
              phone_number: user.phone_number,
              role_id,
              role
            }
          });
        }
      );
    });
  });
});
// ========================= GENERATE OTP (SECURE) =========================
router.post("/otp", (req, res) => {
  const { email, phone_number } = req.body;

  if (!email && !phone_number) {
    return res.status(400).json({
      status: false,
      message: "Email or phone number is required"
    });
  }
 
  if (email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ status: false, message: "Invalid email format" });
    }
  }

  const query = email ? "SELECT * FROM users WHERE email = ?" : "SELECT * FROM users WHERE phone_number = ?";
  const value = email || phone_number;

  db.query(query, [value], (err, results) => {
    if (err) return res.status(500).json({ status: false, message: "Something went wrong" });
 
    if (results.length > 0) {
      const otp = Math.floor(100000 + Math.random() * 900000);
      otpStore[value] = otp;
 
    }

    return res.json({
      status: true,
      message: "If the account exists, an OTP will be sent",
      otp: otpStore[value] 
    });
  });
});

// ========================= UPDATE PROFILE =========================
router.put("/update", verifyToken, (req, res) => {
  const userId = req.user.id;
  const { name, phone_number, email, password } = req.body;

  if (!name) {
    return res.status(400).json({ status: false, message: "Name is required" });
  }
  
 if (name.length < 3 || name.length > 50) {
    return res.status(400).json({ status: false, message: "Name must be between 3 and 50 characters" });
  }

  const nameRegex = /^[A-Za-z0-9\s]+$/;
  if (!nameRegex.test(name)) {
    return res.status(400).json({ status: false, message: "Name can only contain letters and spaces" });
  }

  if (!phone_number || phone_number.trim() === "") {
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

  if (!password) {
    return res.status(400).json({ status: false, message: "Password is required" });
  }

  if (password.length < 6) {
    return res.status(400).json({ status: false, message: "Password must be at least 6 characters long" });
  }

  const updates = ["name = ?", "phone_number = ?", "email = ?", "password = ?"];
  const hashed = bcrypt.hashSync(password, 10);
  const values = [name, phone_number, email, hashed, userId];

  const sql = `UPDATE users SET ${updates.join(", ")} WHERE id = ?`;

  db.query(sql, values, (err) => {
    if (err) {
      if (err.code === "ER_DUP_ENTRY") {
        return res.status(409).json({ status: false, message: "Email already exists" });
      }
      return res.status(500).json({ status: false, message: "Database error" });
    }

    db.query(
      `SELECT u.id, u.name, u.email, u.phone_number,
              r.id AS role_id, r.name AS role
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
       WHERE u.id = ?`,
      [userId],
      (err2, results) => {
        if (err2 || results.length === 0) {
          return res.status(404).json({ status: false, message: "User not found" });
        }

        res.json({
          status: true,
          message: "Profile updated successfully",
          User: results[0]
        });
      }
    );
  });
});
// ========================= LOGOUT =========================
router.post("/logout", verifyToken, logout);
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
      User: results[0]
    });
  });
});

export default router;
