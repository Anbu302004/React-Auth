// routes/auth.js
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "../config/db.js";
import { verifyToken, logout } from "../middleware/auth.js";
import dotenv from "dotenv";
dotenv.config();

const router = express.Router();
const otpStore = {};  
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const phoneRegex = /^[0-9]{10}$/;
const nameRegex = /^[A-Za-z\s]+$/;

function generateToken(payload) { 
  return jwt.sign(payload, process.env.JWT_SECRET);
}

// ========================= REGISTER =========================
router.post("/register", (req, res) => {
  let { name, email, password, phone_number } = req.body || {};

  // Trim inputs
  name = name ? name.trim() : "";
  email = email ? email.trim() : "";
  password = password ? password.trim() : "";
  phone_number = phone_number ? phone_number.trim() : "";

  const errors = [];
 
  if (!name) errors.push("Name is required");
  if (!email) errors.push("Email is required");
  if (!password) errors.push("Password is required");
  if (!phone_number) errors.push("Phone number is required");

  if (errors.length > 0) {
    return res.status(400).json({ status: false, messages: errors });
  }

  if (name.length < 3 || name.length > 50)
    errors.push("Name must be between 3 and 50 characters");
  if (!nameRegex.test(name))
    errors.push("Name can only contain letters and spaces");
  if (!emailRegex.test(email))
    errors.push("Invalid email format");
  if (password.length < 6)
    errors.push("Password must be at least 6 characters long");
  if (!phoneRegex.test(phone_number))
    errors.push("Phone number must be 10 digits");

  if (errors.length > 0) {
    return res.status(400).json({ status: false, messages: errors });
  }

  const hashed = bcrypt.hashSync(password, 10);
 
  db.query(
    "SELECT email, phone_number FROM users WHERE email = ? OR phone_number = ?",
    [email, phone_number],
    (err, result) => {
      if (err) {
        return res.status(500).json({ status: false, messages: ["Database error"] });
      }
 
      const duplicateSet = new Set();
      if (result && result.length > 0) {
        result.forEach(row => {
          if (row.email === email) duplicateSet.add("Email already registered");
          if (row.phone_number === phone_number) duplicateSet.add("Phone number already registered");
        });
      }

      if (duplicateSet.size > 0) {
        return res.status(409).json({ status: false, messages: Array.from(duplicateSet) });
      }
 
      db.query(
        "INSERT INTO users (name, email, password, phone_number, status) VALUES (?,?,?,?, 'active')",
        [name, email, hashed, phone_number],
        (err2, results) => {
          if (err2) {
            return res.status(500).json({ status: false, messages: ["Database error"] });
          }

          const userId = results.insertId;
 
          db.query(
            "SELECT id AS role_id, name AS role_name FROM roles WHERE name = 'user' LIMIT 1",
            (err3, roleRes) => {
              if (err3 || !roleRes.length) {
                return res.status(500).json({ status: false, messages: ["Default role not found"] });
              }

              const roleData = roleRes[0];

              db.query(
                "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
                [userId, roleData.role_id],
                (err4) => {
                  if (err4) {
                    return res.status(500).json({ status: false, messages: ["Role assignment failed"] });
                  }

                  const token = generateToken({
                    id: userId,
                    email,
                    phone_number,
                    role_id: roleData.role_id,
                    role: roleData.role_name
                  });

                  return res.json({
                    status: true,
                    messages: ["User registered successfully"],
                    token,
                    user: {
                      id: userId,
                      name,
                      email,
                      phone_number,
                      role_id: roleData.role_id,
                      role: roleData.role_name,
                      status: "active"
                    }
                  });
                }
              );
            }
          );
        }
      );
    }
  );
});

 // ========================= LOGIN =========================
router.post("/login", (req, res) => {
  let { email, password } = req.body || {};

  email = email ? email.trim() : "";
  password = password ? password.trim() : "";

  const allowedFields = ["email", "password"];
  const extraFields = Object.keys(req.body || {}).filter((k) => !allowedFields.includes(k));
  if (extraFields.length > 0) {
    return res.status(400).json({ status: false, message: `Unexpected field(s): ${extraFields.join(", ")}` });
  }

  if (!email) return res.status(400).json({ status: false, message: "Email is required" });
  if (!emailRegex.test(email)) return res.status(400).json({ status: false, message: "Invalid email format" });
  if (!password) return res.status(400).json({ status: false, message: "Password is required" });
  if (password.length < 6) return res.status(400).json({ status: false, message: "Password must be at least 6 characters long" });

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) return res.status(500).json({ status: false, message: "Database error" });
    if (results.length === 0) return res.status(401).json({ status: false, message: "Incorrect email or password" });

    const user = results[0];
    const uStatus = Number(user.status);  
    if (uStatus === 0) {
      return res.status(403).json({ status: false, message: "Your account has been blocked. Contact admin." });
    }
 
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ status: false, message: "Incorrect email or password" });
 
    if (uStatus === 2) {
      db.query("UPDATE users SET status = ? WHERE id = ?", [1, user.id], (updErr) => { 
        user.status = 1;
        fetchRoleAndRespond(user, res);
      });
    } else { 
      fetchRoleAndRespond(user, res);
    }
  });

  function fetchRoleAndRespond(user, res) {
    db.query(
      `SELECT r.id AS role_id, r.name AS role
       FROM roles r
       JOIN user_roles ur ON ur.role_id = r.id
       WHERE ur.user_id = ?`,
      [user.id],
      (err2, roleResults) => {
        if (err2) return res.status(500).json({ status: false, message: "Database error" });
        if (!roleResults || roleResults.length === 0) return res.status(403).json({ status: false, message: "User has no assigned role" });

        const { role_id, role } = roleResults[0];

        const token = generateToken({
          id: user.id,
          email: user.email,
          phone_number: user.phone_number,
          role_id,
          role
        });

        return res.json({
          status: true,
          message: "Login successful",
          token,
          data: {
            userId: user.id,
            name: user.name,
            email: user.email,
            phone_number: user.phone_number,
            role_id,
            role,
            status: Number(user.status)  
          }
        });
      }
    );
  }
});
// ========================= GENERATE OTP =========================
router.post("/otp", (req, res) => {
  let { email, phone_number } = req.body || {};
  email = email?.trim() || "";
  phone_number = phone_number?.trim() || "";

  if (!email && !phone_number)
    return res.status(400).json({ status: false, message: "Email or phone number is required" });
  if (phone_number && !phoneRegex.test(phone_number))
    return res.status(400).json({ status: false, message: "Phone number must be 10 digits" });
  if (email && !emailRegex.test(email))
    return res.status(400).json({ status: false, message: "Invalid email format" });

  const key = email || phone_number;
  const now = Date.now();

  // Check if user exists
  const query = email ? "SELECT * FROM users WHERE email = ?" : "SELECT * FROM users WHERE phone_number = ?";
  db.query(query, [key], (err, results) => {
    if (err) return res.status(500).json({ status: false, message: "Something went wrong" });

    // Only generate OTP if user exists
    if (results.length > 0) {
      // Reuse existing OTP if still valid
      if (otpStore[key] && otpStore[key].expiresAt > now) {
        return res.json({ status: true, message: "If the account exists, an OTP will be sent", otp: otpStore[key].otp });
      }

      // Generate new OTP
      const otp = Math.floor(100000 + Math.random() * 900000);
      otpStore[key] = { otp, expiresAt: now + 30 * 1000 }; // expires in 30 seconds
      return res.json({ status: true, message: "If the account exists, an OTP will be sent", otp });
    }
 
    return res.json({ status: true, message: "If the account exists, an OTP will be sent" });
  });
});

// ========================= LOGIN OTP =========================
router.post("/login-otp", (req, res) => {
  let { email, phone_number, otp } = req.body || {};
  email = email?.trim() || "";
  phone_number = phone_number?.trim() || "";
  otp = otp?.toString().trim() || "";

  if (!email && !phone_number)
    return res.status(400).json({ status: false, message: "Email or phone number is required" });
  if (!otp)
    return res.status(400).json({ status: false, message: "OTP is required" });

  const key = email || phone_number;
  const stored = otpStore[key];

  if (!stored || stored.otp.toString() !== otp.toString())
    return res.status(401).json({ status: false, message: "Invalid OTP" });

  if (stored.expiresAt < Date.now()) {
    delete otpStore[key];
    return res.status(401).json({ status: false, message: "OTP expired, request a new one" });
  }

  const query = email ? "SELECT * FROM users WHERE email = ?" : "SELECT * FROM users WHERE phone_number = ?";
  db.query(query, [key], (err, results) => {
    if (err) return res.status(500).json({ status: false, message: "Database error" });
    if (!results.length) return res.status(404).json({ status: false, message: "Account not found, please register first" });

    const user = results[0];
    if (Number(user.status) === 0)
      return res.status(403).json({ status: false, message: "Your account has been blocked. Contact admin." });

    const newStatus = Number(user.status) === 2 ? 1 : Number(user.status);

    db.query(
      `UPDATE users SET ${email ? "email_verify" : "phone_verify"} = 1, status = ? WHERE id = ?`,
      [newStatus, user.id],
      (errUpdate) => {
        if (errUpdate) return res.status(500).json({ status: false, message: "Database error" });

        db.query(
          `SELECT r.id AS role_id, r.name AS role
           FROM roles r
           JOIN user_roles ur ON ur.role_id = r.id
           WHERE ur.user_id = ?`,
          [user.id],
          (err2, roleResults) => {
            if (err2) return res.status(500).json({ status: false, message: "Database error" });
            if (!roleResults.length)
              return res.status(403).json({ status: false, message: "User has no assigned role" });

            const { role_id, role } = roleResults[0];
            const token = generateToken({
              id: user.id,
              email: user.email,
              phone_number: user.phone_number,
              role_id,
              role,
            });

            delete otpStore[key];

            return res.json({
              status: true,
              message: "Logged in successfully",
              token,
              data: {
                userId: user.id,
                name: user.name,
                email: user.email,
                phone_number: user.phone_number,
                role_id,
                role,
                status: newStatus,
              },
            });
          }
        );
      }
    );
  });
});

// ========================= Update Profile =========================
router.put("/update", verifyToken, (req, res) => {
  const userId = req.user.id;
  let { name, phone_number, email, password } = req.body || {};

  name = name ? name.trim() : "";
  phone_number = phone_number ? phone_number.trim() : "";
  email = email ? email.trim() : "";
  password = password ? password.trim() : "";

  const nameRegex = /^[A-Za-z\s]+$/;
  const phoneRegex = /^[0-9]{10}$/;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  db.query("SELECT status, email, phone_number FROM users WHERE id = ?", [userId], (err, result) => {
    if (err) return res.status(500).json({ status: false, message: "Database error", error: err.message });
    if (!result || result.length === 0) return res.status(404).json({ status: false, message: "User not found" });

    const user = result[0];
    const userStatus = user.status;

    if (userStatus === "inactive" || userStatus === "deactive") {
      return res.status(403).json({ status: false, message: "Your account is deactivated. Please activate to update your profile." });
    }
    if (userStatus === "blocked") {
      return res.status(403).json({ status: false, message: "Your account is blocked. Contact admin." });
    }
 
    const errors = [];
    if (!name) errors.push("Name is required");
    if (name && (name.length < 3 || name.length > 50)) errors.push("Name must be between 3 and 50 characters");
    if (name && !nameRegex.test(name)) errors.push("Name can only contain letters and spaces");

    if (!phone_number) errors.push("Phone number is required");
    if (phone_number && !phoneRegex.test(phone_number)) errors.push("Phone number must be 10 digits");

    if (!email) errors.push("Email is required");
    if (email && !emailRegex.test(email)) errors.push("Invalid email format");

    if (!password) errors.push("Password is required");
    if (password && password.length < 6) errors.push("Password must be at least 6 characters long");

    if (errors.length > 0) return res.status(400).json({ status: false, messages: errors });

    const hashed = bcrypt.hashSync(password, 10);
 
    const emailChanged = email !== user.email;
    const phoneChanged = phone_number !== user.phone_number;

    let sql = "UPDATE users SET name = ?, phone_number = ?, email = ?, password = ?";
    const params = [name, phone_number, email, hashed];

    if (emailChanged) sql += ", email_verify = 0";
    if (phoneChanged) sql += ", phone_verify = 0";

    sql += " WHERE id = ?";
    params.push(userId);

    db.query(sql, params, (updateErr) => {
      if (updateErr) {
        if (updateErr.code === "ER_DUP_ENTRY") {
          return res.status(409).json({ status: false, message: "Email already exists" });
        }
        return res.status(500).json({ status: false, message: "Database error", error: updateErr.message });
      }

      db.query(
        `SELECT u.id, u.name, u.email, u.phone_number, u.email_verify, u.phone_verify,
                r.id AS role_id, r.name AS role
         FROM users u
         LEFT JOIN user_roles ur ON ur.user_id = u.id
         LEFT JOIN roles r ON r.id = ur.role_id
         WHERE u.id = ?`,
        [userId],
        (err2, results) => {
          if (err2 || !results || results.length === 0) {
            return res.status(404).json({ status: false, message: "User not found" });
          }
          return res.json({ status: true, message: "Profile updated successfully", data: results[0] });
        }
      );
    });
  });
});

// ========================= LOGOUT =========================
router.post("/logout", verifyToken, logout);

// ========================= ME =========================
router.get("/me", verifyToken, (req, res) => {
  const userId = req.user.id;
  db.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
    if (err) return res.status(500).json({ status: false, message: "Database error" });
    if (!results || results.length === 0) return res.status(404).json({ status: false, message: "User not found" });
    return res.json({ status: true, message: "Profile fetched successfully", user: results[0] });
  });
});

export default router;
