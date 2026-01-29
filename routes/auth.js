// routes/auth.js
import express from "express";
import bcrypt from "bcryptjs"; 
import db from "../config/db.js";
import { v4 as uuidv4 } from "uuid";
import { verifyToken, logout } from "../middleware/auth.js"; 
import crypto from "crypto";


const router = express.Router();
const otpStore = {};  
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const phoneRegex = /^[0-9]{10}$/;
const nameRegex = /^[A-Za-z\s]+$/;
const resetPasswordStore = {};

// ========================= SESSION CREATION =========================
export async function createSession(userId, req) { 
  const token = uuidv4();
 
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket.remoteAddress ||
    "unknown";
 
  const device = req.headers["user-agent"] || "unknown";
 
  await db.query(
    `INSERT INTO user_details
     (user_id, token_id, profile_id, token, ip_address, device, last_login)
     VALUES (?, NULL, NULL, ?, ?, ?, NOW())`,
    [userId, token, ip, device]
  );
 
  await db.query(
    `DELETE FROM user_details WHERE last_login < NOW() - INTERVAL 3 MONTH`
  );

  return token;  
}
// ========================= REGISTER =========================
router.post("/register", async (req, res) => {
  try {
    let { name, email, password, phone_number } = req.body || {};
    name = name?.trim() || "";
    email = email?.trim() || "";
    password = password?.trim() || "";
    phone_number = phone_number?.trim() || "";

    const errors = [];
    if (!name) errors.push("Name is required");
    if (!email) errors.push("Email is required");
    if (!password) errors.push("Password is required");
    if (!phone_number) errors.push("Phone number is required");
    if (name && (name.length < 3 || name.length > 50)) errors.push("Name must be between 3 and 50 characters");
    if (name && !nameRegex.test(name)) errors.push("Name can only contain letters and spaces");
    if (email && !emailRegex.test(email)) errors.push("Invalid email format");
    if (password && password.length < 6) errors.push("Password must be at least 6 characters long");
    if (phone_number && !phoneRegex.test(phone_number)) errors.push("Phone number must be 10 digits");
    if (errors.length) return res.status(400).json({ status: false, messages: errors });

    const hashed = bcrypt.hashSync(password, 10);

    // Check duplicates
    const [existing] = await db.query(
      "SELECT email, phone_number FROM users WHERE email = ? OR phone_number = ?",
      [email, phone_number]
    );

    const duplicateSet = new Set();
    existing.forEach(row => {
      if (row.email === email) duplicateSet.add("Email already registered");
      if (row.phone_number === phone_number) duplicateSet.add("Phone number already registered");
    });

    if (duplicateSet.size > 0) {
      return res.status(409).json({ status: false, messages: Array.from(duplicateSet) });
    }

    // Insert user
    const [result] = await db.query(
      "INSERT INTO users (name, email, password, phone_number, status) VALUES (?,?,?,?, '1')",
      [name, email, hashed, phone_number]
    );
    const userId = result.insertId;

    // Assign default role
    const [roleRes] = await db.query(
      "SELECT id AS role_id, name AS role_name FROM roles WHERE name = 'user' LIMIT 1"
    );

    if (!roleRes.length) return res.status(500).json({ status: false, messages: ["Default role not found"] });

    const roleData = roleRes[0];
    await db.query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", [userId, roleData.role_id]);

    // Create session
    const token = await createSession(userId, req);

    return res.json({
      status: true,
      messages: ["User registered successfully"], 
      user: {
        id: userId,
        name,
        email,
        phone_number,
        token,
        role_id: roleData.role_id,
        role: roleData.role_name,
        status: "active"
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: false, messages: ["Server error"] });
  }
});

// ========================= LOGIN =========================
router.post("/login", async (req, res) => {
  try {
    let { email, phone_number, password } = req.body || {};
    const identifier = (email || phone_number || "").trim();
    password = password?.trim() || "";

    if (!identifier || !password)
      return res.status(400).json({ status: false, message: "Email/Phone and password are required" });

    const [results] = await db.query(
      "SELECT * FROM users WHERE email = ? OR phone_number = ?",
      [identifier, identifier]
    );

    if (!results.length)
      return res.status(401).json({ status: false, message: "Incorrect email/phone or password" });

    const user = results[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword)
      return res.status(401).json({ status: false, message: "Incorrect email/phone or password" });

    if (Number(user.status) === 0)
      return res.status(403).json({ status: false, message: "Your account has been blocked. Contact admin." });

    if (Number(user.status) === 2) {
      await db.query("UPDATE users SET status = 1 WHERE id = ?", [user.id]);
      user.status = 1;
    }

    const [roleResults] = await db.query(
      `SELECT r.id AS role_id, r.name AS role
       FROM roles r
       JOIN user_roles ur ON ur.role_id = r.id
       WHERE ur.user_id = ?`,
      [user.id]
    );

    if (!roleResults.length)
      return res.status(403).json({ status: false, message: "User has no assigned role" });

    const { role_id, role } = roleResults[0];
    const token = await createSession(user.id, req);

    return res.json({
      status: true,
      message: "Login successful",
      data: {
        userId: user.id,
        name: user.name,
        email: user.email,
        phone_number: user.phone_number,
        token,
        role_id,
        role,
        status: Number(user.status)
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: false, message: "Server error" });
  }
});

// ========================= GENERATE OTP =========================
router.post("/otp", async (req, res) => {
  try {
    let { email, phone_number } = req.body || {};
    email = email?.trim();
    phone_number = phone_number?.trim();

    if (!email && !phone_number) return res.status(400).json({ status: false, message: "Email or phone number is required" });
    if (phone_number && !phoneRegex.test(phone_number)) return res.status(400).json({ status: false, message: "Phone number must be 10 digits" });
    if (email && !emailRegex.test(email)) return res.status(400).json({ status: false, message: "Invalid email format" });

    const key = email || phone_number;
    const now = Date.now();

    const query = email ? "SELECT * FROM users WHERE email = ?" : "SELECT * FROM users WHERE phone_number = ?";
    const [results] = await db.query(query, [key]);

    if (results.length > 0) {
      if (otpStore[key] && otpStore[key].expiresAt > now) {
        return res.json({ status: true, message: "If the account exists, an OTP will be sent", otp: otpStore[key].otp });
      }

      const otp = Math.floor(100000 + Math.random() * 900000);
      otpStore[key] = { otp, expiresAt: now + 30 * 1000 };
      return res.json({ status: true, message: "If the account exists, an OTP will be sent", otp });
    }

    return res.json({ status: true, message: "If the account exists, an OTP will be sent" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: false, message: "Server error" });
  }
});

// ========================= LOGIN OTP =========================
 router.post("/login-otp", async (req, res) => {
  try {
    let { email, phone_number, otp } = req.body || {};
    email = email?.trim();
    phone_number = phone_number?.trim();
    otp = otp?.toString()?.trim();

    if (!email && !phone_number)
      return res.status(400).json({ status: false, message: "Email or phone number is required" });
    if (!otp)
      return res.status(400).json({ status: false, message: "OTP is required" });

    const key = email || phone_number;
    const stored = otpStore[key];

    if (!stored || stored.otp.toString() !== otp)
      return res.status(401).json({ status: false, message: "Invalid OTP" });

    if (stored.expiresAt < Date.now()) {
      delete otpStore[key];
      return res.status(401).json({ status: false, message: "OTP expired, request a new one" });
    }

    const query = email
      ? "SELECT * FROM users WHERE email = ?"
      : "SELECT * FROM users WHERE phone_number = ?";
    const [results] = await db.query(query, [key]);

    if (!results.length)
      return res.status(404).json({ status: false, message: "Account not found, please register first" });

    const user = results[0];
 
    if (Number(user.status) === 0)
      return res.status(403).json({ status: false, message: "Your account has been blocked. Contact admin." });
 
    if (Number(user.status) === 2) {
      await db.query("UPDATE users SET status = 1 WHERE id = ?", [user.id]);
      user.status = 1;
    }

    const [roleResults] = await db.query(
      `SELECT r.id AS role_id, r.name AS role
       FROM roles r
       JOIN user_roles ur ON ur.role_id = r.id
       WHERE ur.user_id = ?`,
      [user.id]
    );

    if (!roleResults.length)
      return res.status(403).json({ status: false, message: "User has no assigned role" });

    const { role_id, role } = roleResults[0];
    const token = await createSession(user.id, req);

    if (email) {
      await db.query("UPDATE users SET email_verify = 1 WHERE id = ?", [user.id]);
    } else if (phone_number) {
      await db.query("UPDATE users SET phone_verify = 1 WHERE id = ?", [user.id]);
    }

    delete otpStore[key];

    return res.json({
      status: true,
      message: "Logged in successfully", 
      data: {
        userId: user.id,
        name: user.name,
        email: user.email,
        phone_number: user.phone_number,
        token,
        role_id,
        role,
        status: Number(user.status)
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: false, message: "Server error" });
  }
});

// ========================= FORGET PASSWROD =========================
 router.post("/forgot-password", async (req, res) => {
  try {
    let { email } = req.body || {};

    email = email?.trim().toLowerCase();

    if (!email) {
      return res.status(400).json({
        status: false,
        message: "Email is required"
      });
    }

    if (!emailRegex.test(email)) {
      return res.status(400).json({
        status: false,
        message: "Invalid email"
      });
    }

    const [users] = await db.query(
      "SELECT id FROM users WHERE LOWER(email)=? LIMIT 1",
      [email]
    );

    // Always respond with success to avoid revealing email existence
    if (!users.length) {
      return res.json({
        status: true,
        message: "If the account exists, a reset token will be sent"
      });
    }

    const now = Date.now();

    // Reuse token if still valid (within 30 seconds)
    if (resetPasswordStore[email] && resetPasswordStore[email].expiresAt > now) {
      return res.json({
        status: true,
        message: "Reset token generated",
        token: resetPasswordStore[email].token
      });
    }

    // Generate a new token
    const token = crypto.randomBytes(32).toString("hex");
    resetPasswordStore[email] = {
      token,
      expiresAt: now + 30 * 1000 // 30 seconds expiry
    };

    return res.json({
      status: true,
      message: "Reset token generated",
      token
    });

  } catch (err) {
    console.error("FORGOT PASSWORD ERROR 👉", err);
    return res.status(500).json({
      status: false,
      message: "Server error"
    });
  }
}); 
// ========================= RESET PASSWORD WITHOUT EMAIL =========================
router.post("/reset-password", async (req, res) => {
  try {
    let { token, new_password, confirm_password } = req.body || {};

    if (!token) {
      return res.status(400).json({
        status: false, 
        message: "Token is required"
      });
    }

    if (!new_password || new_password.length < 6) {
      return res.status(400).json({
        status: false,
        message: "New password must be at least 6 characters long"
      });
    }

    if (!confirm_password) {
      return res.status(400).json({
        status: false,
        message: "Confirm password is required"
      });
    }

    if (new_password !== confirm_password) {
      return res.status(400).json({
        status: false,
        message: "Passwords do not match"
      });
    }

    // Find the email corresponding to the token
    const email = Object.keys(resetPasswordStore).find(
      (key) => resetPasswordStore[key].token === token
    );

    if (!email || Date.now() > resetPasswordStore[email].expiresAt) {
      delete resetPasswordStore[email];
      return res.status(400).json({
        status: false,
        message: "Invalid or expired token"
      });
    }

    // Token is valid, update password
    const hashedPassword = await bcrypt.hash(new_password, 10);

    await db.query(
      "UPDATE users SET password=? WHERE LOWER(email)=?",
      [hashedPassword, email]
    );

    // Remove token after successful reset
    delete resetPasswordStore[email];

    return res.json({
      status: true,
      message: "Password reset successful"
    });

  } catch (err) {
    console.error("RESET PASSWORD ERROR", err);
    return res.status(500).json({
      status: false,
      message: "Server error"
    });
  }
});// ========================= UPDATE PROFILE =========================
 router.put("/update", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    let { name, phone_number, email, profile_image } = req.body || {};

    // Debug logging
    console.log('🔍 DEBUG - Received data:');
    console.log('- userId:', userId);
    console.log('- name:', name);
    console.log('- email:', email);
    console.log('- phone_number:', phone_number);
    console.log('- profile_image length:', profile_image?.length || 0);
    console.log('- profile_image is undefined?', profile_image === undefined);

    // Trim and process data (DON'T set profile_image to null)
    name = name?.trim();
    phone_number = phone_number?.trim();
    email = email?.trim().toLowerCase();
    // Leave profile_image as-is (undefined if not provided)

    console.log('🔍 After processing:');
    console.log('- profile_image is undefined?', profile_image === undefined);

    const [userResult] = await db.query(
      "SELECT status, email, phone_number FROM users WHERE id = ?",
      [userId]
    );

    if (!userResult.length)
      return res.status(404).json({
        status: false,
        messages: ["User not found"]
      });

    const user = userResult[0];

    if (["inactive", "deactive"].includes(user.status))
      return res.status(403).json({
        status: false,
        messages: ["Your account is deactivated. Please activate to update your profile."]
      });

    if ("password" in req.body)
      return res.status(400).json({
        status: false,
        messages: ["Password is not allowed in profile update. Use reset password."]
      });

    if (user.status === "blocked")
      return res.status(403).json({
        status: false,
        messages: ["Your account is blocked. Contact admin."]
      });

    /* ================= Validations ================= */
    const errors = [];

    if (!name) errors.push("Name is required");
    if (name && (name.length < 3 || name.length > 50))
      errors.push("Name must be between 3 and 50 characters");
    if (name && !/^[A-Za-z\s]+$/.test(name))
      errors.push("Name can only contain letters and spaces");

    if (!phone_number) errors.push("Phone number is required");
    if (phone_number && !/^[0-9]{10}$/.test(phone_number))
      errors.push("Phone number must be 10 digits");

    if (!email) errors.push("Email is required");
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      errors.push("Invalid email format");

    if (errors.length)
      return res.status(400).json({
        status: false,
        messages: errors
      });

    /* ================= Uniqueness Checks ================= */
    if (email !== user.email) {
      const [emailExists] = await db.query(
        "SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1",
        [email, userId]
      );

      if (emailExists.length)
        return res.status(409).json({
          status: false,
          messages: ["Email already exists"]
        });
    }

    if (phone_number !== user.phone_number) {
      const [phoneExists] = await db.query(
        "SELECT id FROM users WHERE phone_number = ? AND id != ? LIMIT 1",
        [phone_number, userId]
      );

      if (phoneExists.length)
        return res.status(409).json({
          status: false,
          messages: ["Phone number already exists"]
        });
    }

    /* ================= Update ================= */
    const emailChanged = email !== user.email;
    const phoneChanged = phone_number !== user.phone_number;

    console.log('🔍 Preparing SQL query...');
    
    // ⭐ BUILD SQL DYNAMICALLY - only update profile_image if provided
    let sql = "UPDATE users SET name = ?, phone_number = ?, email = ?";
    const params = [name, phone_number, email];

    // ⭐ CRITICAL FIX: Only update profile_image if it was explicitly provided in request
    if (profile_image !== undefined) {
      sql += ", profile_image = ?";
      params.push(profile_image);
      console.log('✅ Including profile_image in update (length:', profile_image?.length || 0, ')');
    } else {
      console.log('⏭️ Skipping profile_image update - keeping existing value in database');
    }

    if (emailChanged) sql += ", email_verify = 0";
    if (phoneChanged) sql += ", phone_verify = 0";

    sql += " WHERE id = ?";
    params.push(userId);

    console.log('🔍 Final SQL:', sql);
    console.log('🔍 Params count:', params.length);

    await db.query(sql, params);

    console.log('✅ Update successful, fetching updated data...');

    const [updatedResults] = await db.query(
      `SELECT u.id, u.name, u.email, u.phone_number,
              u.profile_image,
              u.email_verify, u.phone_verify,
              r.id AS role_id, r.name AS role
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
       WHERE u.id = ?`,
      [userId]
    );

    console.log('✅ Profile updated successfully!');
    console.log('📤 Returning data with profile_image:', updatedResults[0].profile_image ? 'YES' : 'NO');

    return res.json({
      status: true,
      message: "Profile updated successfully",
      data: updatedResults[0]
    });

  } catch (err) {
    console.error('❌ ERROR in /update route:');
    console.error('Error name:', err.name);
    console.error('Error message:', err.message);
    console.error('Error stack:', err.stack);

    return res.status(500).json({
      status: false,
      messages: ["Server error"]
    });
  }
});
// ========================= LOGOUT =========================
router.post("/logout", verifyToken, logout);

// ========================= ME =========================
router.get("/me", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const [results] = await db.query("SELECT * FROM users WHERE id = ?", [userId]);
    if (!results.length) return res.status(404).json({ status: false, message: "User not found" });
    return res.json({ status: true, message: "Profile fetched successfully", user: results[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: false, message: "Server error" });
  }
});

export default router;
