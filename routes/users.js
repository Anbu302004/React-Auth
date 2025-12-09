import express from "express";
import { verifyToken } from "../middleware/auth.js";
import db from "../config/db.js";
const router = express.Router(); 
// ========================= Get Profile =========================
router.get("/profile", verifyToken, (req, res) => {
    const userId = req.user.id;
    db.query(
        "SELECT id, name, email, phone_number FROM users WHERE id = ?",
        [userId],
        (err, results) => {
            if (err) {
                return res.status(500).json({
                    status: false,
                    message: "Database error",
                    error: err.message
                });
            }
            if (results.length === 0) {
                return res.status(404).json({
                    status: false,
                    message: "User not found"
                });
            }
            return res.json({
                status: true,
                message: "Profile fetched successfully",
                data: results[0]
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
            message: `${userRole} is not allowed to deactivate their own account`
        });
    }
    db.query(
        "UPDATE users SET status = 'inactive' WHERE id = ?",
        [userId],
        (err, result) => {
            if (err) {
                return res.status(500).json({
                    status: false,
                    message: "Database error",
                    error: err.message
                });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({
                    status: false,
                    message: "User not found"
                });
            }
            return res.json({
                status: true,
                message: "Account deactivated successfully"
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
            message: `${userRole} is not allowed to delete their own account`
        });
    }
    db.query("DELETE FROM users WHERE id = ?", [userId], (err, result) => {
        if (err) {
            return res.status(500).json({
                status: false,
                message: "Database error",
                error: err.message
            });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({
                status: false,
                message: "User not found"
            });
        }
        return res.json({
            status: true,
            message: "Your account has been deleted successfully"
        });
    });
});


export default router;