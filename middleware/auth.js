import db from "../config/db.js";

// Middleware to verify UUID token and attach user info
export const verifyToken = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers["authorization"];
    const token = authHeader?.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        status: false,
        message: "Token missing",
      });
    }

    // Fetch user info and role using token column
    const [rows] = await db.query(
      `SELECT u.id AS user_id, u.name, u.email, u.status, r.name AS role
       FROM user_details ud
       JOIN users u ON ud.user_id = u.id
       LEFT JOIN user_roles ur ON u.id = ur.user_id
       LEFT JOIN roles r ON ur.role_id = r.id
       WHERE ud.token = ?`,
      [token]
    );

    if (!rows.length) {
      return res.status(401).json({
        status: false,
        message: "Invalid or expired token",
      });
    }

    // Update last login
    try {
      await db.query("UPDATE user_details SET last_login = NOW() WHERE token = ?", [token]);
    } catch (err) {
      console.error("Failed to update last_login:", err);
    }

    // Attach user info to req.user
    req.user = {
      user_id: rows[0].user_id,
      id: rows[0].user_id,   // can use either id or user_id in routes
      name: rows[0].name,
      email: rows[0].email,
      status: rows[0].status,
      role: rows[0].role || "user",
      token: token,          // store actual token
    };

    next();
  } catch (err) {
    console.error("Token verification error:", err);
    return res.status(500).json({
      status: false,
      message: "Internal server error",
    });
  }
};
// Logout route
export const logout = async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader?.split(" ")[1];

    if (!token) {
      return res.status(400).json({
        status: false,
        message: "Token missing",
      });
    }

    const userId = req.user.id; // from verifyToken
    const { mode, session_ids } = req.body || {};

    let query = "";
    let params = [];

    // ================= LOGOUT ALL DEVICES =================
    if (mode === "all") {
      query = `
        UPDATE user_details
        SET token_id = NULL, token = NULL
        WHERE user_id = ?
      `;
      params = [userId];

    // ================= LOGOUT SELECTED SESSIONS =================
    } else if (mode === "selected") {
      if (!Array.isArray(session_ids) || session_ids.length === 0) {
        return res.status(400).json({
          status: false,
          message: "Provide session_ids array to logout",
        });
      }

      query = `
        UPDATE user_details
        SET token_id = NULL, token = NULL
        WHERE id IN (${session_ids.map(() => "?").join(",")})
          AND user_id = ?
      `;
      params = [...session_ids, userId];

    // ================= LOGOUT CURRENT SESSION =================
    } else {
      query = `
        UPDATE user_details
        SET token_id = NULL, token = NULL
        WHERE token = ? AND user_id = ?
      `;
      params = [token, userId];
    }

    const [result] = await db.query(query, params);

    if (result.affectedRows === 0) {
      return res.status(400).json({
        status: false,
        message: "No matching sessions found for this user",
      });
    }

    return res.json({
      status: true,
      message: "Logout successful",
      mode: mode || "current",
      count: result.affectedRows,
    });

  } catch (err) {
    console.error("Logout error:", err);
    return res.status(500).json({
      status: false,
      message: "Internal server error",
    });
  }
};
