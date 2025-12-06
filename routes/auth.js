import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "../config/db.js";
import { verifyToken } from "../middleware/auth.js";
import dotenv from "dotenv";
dotenv.config();

const router = express.Router();

const otpStore = {};


router.post("/register", (req, res) => {
  const { name, email, password, phone_number } = req.body;

  const hashed = bcrypt.hashSync(password, 10);

  db.query(
    "INSERT INTO users (name, email, password, phone_number) VALUES (?,?,?,?)",
    [name, email, hashed, phone_number],
    (err) => {
      if (err) return res.status(500).json({ error: err });
      res.json({ message: "User registered successfully" });
    }
  );
});

router.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err || results.length === 0)
        return res.status(400).json({ error: "User not found" });

      const user = results[0];
      const validPassword = await bcrypt.compare(password, user.password);

      if (!validPassword)
        return res.status(401).json({ error: "Invalid password" });

      const token = jwt.sign(
        { id: user.id, email: user.email, phone_number: user.phone_number  },
        process.env.JWT_SECRET
      );

      res.json({ message: "Login success", token });
    }
  );
});

router.post("/generate-otp", (req, res) => {
  const { email, phone_number } = req.body;

  if (!email && !phone_number) {
    return res.status(400).json({ error: "Email or phone number is required" });
  }

  let query = "";
  let value = "";

  if (email) {
    query = "SELECT * FROM users WHERE email = ?";
    value = email;
  } else if (phone_number) {
    query = "SELECT * FROM users WHERE phone_number = ?";
    value = phone_number;
  }

  db.query(query, [value], (err, results) => {
    if (err || results.length === 0)
      return res.status(404).json({ error: "User not found" });

    const otp = Math.floor(100000 + Math.random() * 900000);
 
    otpStore[value] = otp;

    res.json({
      message: "OTP generated successfully",
      otp: otp 
    });
  });
});

router.post("/login-otp", (req, res) => {
  const { email, phone_number, otp } = req.body;
 
  if ((!email && !phone_number) || !otp) {
    return res.status(400).json({ error: "Email or phone number and OTP are required" });
  }
 
  const key = email || phone_number;
  if (otpStore[key] != otp) {
    return res.status(401).json({ error: "Invalid OTP" });
  }
 
  const query = email ? "SELECT * FROM users WHERE email = ?" : "SELECT * FROM users WHERE phone_number = ?";
  const value = email || phone_number;
 
  db.query(query, [value], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = results[0];
 
    const updateField = email ? "email_verify" : "phone_verify";
    db.query(`UPDATE users SET ${updateField} = 1 WHERE ${email ? "email" : "phone_number"} = ?`, [value]);
 
    const token = jwt.sign(
      { id: user.id, email: user.email, phone_number: user.phone_number },
      process.env.JWT_SECRET
    );
 
    delete otpStore[key];
 
    res.json({ message: "OTP Login success", token });
  });
});

router.put("/update-profile", verifyToken, (req, res) => {
  const userId = req.user.id;
  const { name, phone_number, email, password } = req.body;

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
    return res.status(400).json({ error: "No fields to update" });
  }

  values.push(userId);

  const sql = `UPDATE users SET ${updates.join(", ")} WHERE id = ?`;

  db.query(sql, values, (err) => {
    if (err) {
      return res.status(500).json({ error: err });
    }
 
    db.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
      if (err || results.length === 0) {
        return res.status(404).json({ error: "User not found after update" });
      }

      res.json({
        message: "Profile updated successfully",
        user: results[0],
      });
    });
  });
});

router.post("/logout", verifyToken, (req, res) => {
  res.json({ message: "Logout successful" });
})

router.get("/me", verifyToken, (req, res) => {
  const userId = req.user.id;

  db.query("SELECT * FROM users WHERE id = ?", [userId],
    (err, results) => {
      if (err || results.length === 0)
        return res.status(404).json({ error: "User not found" });

      res.json({ user: results[0] });
    }
  );
});



 


export default router;
