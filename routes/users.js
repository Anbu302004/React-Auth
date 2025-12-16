import express from "express";
import { verifyToken } from "../middleware/auth.js";
import db from "../config/db.js";
const router = express.Router();

// ========================= Get Profile =========================
router.get("/profile", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const [results] = await db.query(
      "SELECT id, name, email, phone_number, status, password FROM users WHERE id = ?",
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
          status: user.status
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