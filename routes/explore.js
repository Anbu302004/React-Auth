import express from "express";
import db from "../config/db.js";
import { verifyToken } from "../middleware/auth.js";

const router = express.Router();
 
router.get("/explore", verifyToken, (req, res) => {
  db.query("SELECT * FROM  explore", (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json({explore: results });
  });
});

router.get("/explore_link", verifyToken, (req, res) =>{
    db.query("SELECT * FROM  explore_link", (err, results) =>{
        if(err) return res.status(500).json({error: err});
        res.json({explore_link: results});
    })
})
export default router;
