import express from "express";
import { verifyToken } from "../middleware/auth.js";
import db from "../config/db.js";
const router = express.Router();

// ========================= Get Profile =========================
router.get("/profile", verifyToken, (req, res) => {
    const userId = req.user.id;

    db.query(
        "SELECT id, name, email, phone_number, status, password FROM users WHERE id = ?",
        [userId],
        (err, results) => {
            if (err) {
                return res.status(500).json({
                    status: false,
                    messages: ["Database error"],
                    data: []
                });
            }

            if (results.length === 0) {
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
                    messages: [
                        "Account is deactivated. Please login using OTP to activate."
                    ],
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
        }
    );
});

// ========================= Deactivate Profile =========================
router.put("/deactivate", verifyToken, (req, res) => {
    const userId = req.user.id;
    const userRole = req.user.role;

    if (userRole === "admin" || userRole === "subadmin") {
        return res.status(403).json({
            status: false,
            messages: [`${userRole} is not allowed to deactivate their own account`],
            data: []
        });
    }

    db.query(
        "UPDATE users SET status = 2 WHERE id = ?",
        [userId],
        (err, result) => {
            if (err) {
                return res.status(500).json({
                    status: false,
                    messages: ["Database error"],
                    data: []
                });
            }

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
        }
    );
});

// ========================= Delete Profile =========================
router.delete("/delete", verifyToken, (req, res) => {
    const userId = req.user.id;
    const userRole = req.user.role;

    if (userRole === "admin" || userRole === "subadmin") {
        return res.status(403).json({
            status: false,
            messages: [`${userRole} is not allowed to delete their own account`],
            data: []
        });
    }

    db.query("DELETE FROM users WHERE id = ?", [userId], (err, result) => {
        if (err) {
            return res.status(500).json({
                status: false,
                messages: ["Database error"],
                data: []
            });
        }

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
    });
});

export default router;
