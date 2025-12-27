import express from "express";
import db from "../config/db.js";
import {verifyToken} from "../middleware/auth.js";

const router = express.Router();

router.get("/pages", verifyToken, (req, res) => {
    db.query("SELECT * FROM pages", (err, results) => {
        if(err) return res.status(500).json({error: err});
        res.json({pages: results});
    })
})

router.get("/page_gallery", verifyToken, (req, res) => {
    db.query("SELECT * FROM page_gallery", (err, results) => {
        if(err) return res.status(500).json({error: err});
        res.json({page_gallery: results});
    })
})

export default router;