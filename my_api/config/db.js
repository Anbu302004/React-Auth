import mysql from "mysql2";

export const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "", 
  database: "testapi"
});

db.connect((err) => {
  if (err) console.log("DB Error:", err);
  else console.log("Database Connected!");
});


 export default db;