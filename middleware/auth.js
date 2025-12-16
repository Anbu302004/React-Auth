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

    // Fetch user info and role using token_id
    const [rows] = await db.query(
      `SELECT u.id AS user_id, u.name, u.email, u.status, r.name AS role
       FROM user_details ud
       JOIN users u ON ud.user_id = u.id
       LEFT JOIN user_roles ur ON u.id = ur.user_id
       LEFT JOIN roles r ON ur.role_id = r.id
       WHERE ud.token_id = ?`,
      [token]
    );

    if (!rows.length) {
      return res.status(401).json({
        status: false,
        message: "Invalid or expired token",
      });
    }

    // Optional: Update last login
    try {
      await db.query("UPDATE user_details SET last_login = NOW() WHERE token_id = ?", [token]);
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
      token_id: token,
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

    const { mode, tokens } = req.body || {};
    let query = "";
    let params = [];

    if (mode === "all") {
      // Logout from all devices (invalidate tokens only)
      query = `
        UPDATE user_details
        SET token_id = NULL, token = NULL
        WHERE user_id = (
          SELECT user_id FROM (
            SELECT user_id FROM user_details WHERE token_id = ?
          ) t
        )
      `;
      params = [token];

    } else if (mode === "selected") {
      if (!Array.isArray(tokens) || tokens.length === 0) {
        return res.status(400).json({
          status: false,
          message: "Provide tokens array to logout",
        });
      }

      query = `
        UPDATE user_details
        SET token_id = NULL, token = NULL
        WHERE token_id IN (${tokens.map(() => "?").join(",")})
      `;
      params = tokens;

    } else {
      // Current device logout
      query = `
        UPDATE user_details
        SET token_id = NULL, token = NULL
        WHERE token_id = ?
      `;
      params = [token];
    }

    const [result] = await db.query(query, params);

    if (result.affectedRows === 0) {
      return res.status(400).json({
        status: false,
        message: "Token not found or already logged out",
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
