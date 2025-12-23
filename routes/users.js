import express from "express";
import { verifyToken } from "../middleware/auth.js";
import bcrypt from "bcryptjs";
import db from "../config/db.js";
const router = express.Router();

// ========================= Get Profile =========================
router.get("/profile", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const [results] = await db.query(
      "SELECT id, name, email, phone_number, status, password, email_verify, phone_verify FROM users WHERE id = ?",
      [userId]
    );

    if (!results.length) {
      return res.status(404).json({
        status: false,
        messages: ["User not found"],
        data: []
      });
    }

    const user = results[0];

    if (user.status === 2) {
      return res.status(403).json({
        status: false,
        messages: ["Account is deactivated. Please login using OTP to activate."],
        data: []
      });
    }

    if (user.status === 0) {
      return res.status(403).json({
        status: false,
        messages: ["Account is blocked. Contact support."],
        data: []
      });
    }

    return res.json({
      status: true,
      data: [
        {
          id: user.id,
          name: user.name,
          email: user.email,
          phone_number: user.phone_number,
          status: user.status,
          email_verify: user.email_verify,
          phone_verify: user.phone_verify
        }
      ]
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      status: false,
      messages: ["Database error"],
      data: []
    });
  }
});

// ========================= Reset Password =========================
router.put("/reset-password", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({
        status: false,
        messages: ["All fields are required"], 
      });
    }
 
    const [results] = await db.query(
      "SELECT password FROM users WHERE id = ?",
      [userId]
    );

    if (!results.length) {
      return res.status(404).json({
        status: false,
        messages: ["User not found"], 
      });
    }

    const user = results[0];

    // Check current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({
        status: false,
        messages: ["Current password is incorrect"], 
      });
    }

    // Check new password match
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        status: false,
        messages: ["New password and confirm password do not match"], 
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password in DB
    await db.query("UPDATE users SET password = ? WHERE id = ?", [
      hashedPassword,
      userId
    ]);

    return res.json({
      status: true,
      messages: ["Password updated successfully"], 
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({
      status: false,
      messages: ["Database error"], 
    });
  }
});

// ========================= Deactivate Profile =========================
router.put("/deactivate", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;

    if (userRole === "admin" || userRole === "subadmin") {
      return res.status(403).json({
        status: false,
        messages: [`${userRole} is not allowed to deactivate their own account`],
        data: []
      });
    }

    const [result] = await db.query(
      "UPDATE users SET status = 2 WHERE id = ?",
      [userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        status: false,
        messages: ["User not found"],
        data: []
      });
    }

    return res.json({
      status: true,
      messages: ["Account deactivated successfully", "You have been logged out"],
      data: [],
      logout: true
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      status: false,
      messages: ["Database error"],
      data: []
    });
  }
});

// ========================= Get ALL Active Tokens of Logged-in User =========================
router.get("/tokens", verifyToken, async (req, res) => {
  try {
    const userId = Number(req.user.id);

    if (!userId) {
      return res.status(400).json({
        status: false,
        messages: ["Invalid user"],
        data: []
      });
    }

    const [tokens] = await db.query(
      `SELECT 
         id,
         user_id,
         token AS token_id,
         ip_address AS ip,
         device,
         created_at
       FROM user_details
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [userId]
    );

    return res.json({
      status: true,
      user_id: userId,    
      count: tokens.length,
      message:
        tokens.length === 0
          ? "No active sessions found"
          : "Active sessions retrieved successfully",
      data: tokens
    });

  } catch (err) {
    console.error("Get tokens error:", err);
    return res.status(500).json({
      status: false,
      messages: ["Database error"],
      data: []
    });
  }
});
 

// ========================= Delete Profile =========================
router.delete("/delete", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;

    // 🚫 Admin restriction (unchanged)
    if (userRole === "admin" || userRole === "subadmin") {
      return res.status(403).json({
        status: false,
        messages: [`${userRole} is not allowed to delete their own account`],
        data: []
      });
    }

    // 🔍 Check user status first
    const [userResult] = await db.query(
      "SELECT status FROM users WHERE id = ?",
      [userId]
    );

    if (!userResult.length) {
      return res.status(404).json({
        status: false,
        messages: ["User not found"],
        data: []
      });
    }

    // ❌ If inactive / deactivated
    if (Number(userResult[0].status) === 2) {
      return res.status(403).json({
        status: false,
        messages: [
          "Your account is deactivated. Please activate your account before deleting."
        ],
        data: []
      });
    }

    // ✅ Delete allowed only if active
    const [result] = await db.query(
      "DELETE FROM users WHERE id = ?",
      [userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        status: false,
        messages: ["User not found"],
        data: []
      });
    }

    return res.json({
      status: true,
      messages: ["Your account has been deleted successfully"],
      data: []
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({
      status: false,
      messages: ["Database error"],
      data: []
    });
  }
});
export default router;