import express from "express";
import db from "../config/db.js";
import { verifyToken } from "../middleware/auth.js";

const router = express.Router();
 
router.get("/categories", verifyToken, (req, res) => {
  db.query("SELECT * FROM categories", (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ categories: results });
  });
});

router.get("/categories_link", verifyToken, (req, res) =>{
    db.query("SELECT * FROM categories_link", (err, results) =>{
        if(err) return res.status(500).json({error: err});
        res.json({categories_link: results});
    })
})
export default router;
