import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const tokenBlacklist = new Set();

export const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; 

  if (!token) return res.status(401).json({ status: false, message: "Token missing" });

  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ status: false, message: "Token is invalidated" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ status: false, message: "Invalid token" });

    req.user = decoded; 
    next();
  });
};

export const logout = (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (token) tokenBlacklist.add(token);

  res.json({ status: true, message: "Logout successful" });
};
