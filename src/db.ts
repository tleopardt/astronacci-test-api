import mysql from 'mysql2';
import dotenv from 'dotenv';

dotenv.config();

export const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

db.connect();
// db.connect((err) => {
//   if (err) {
//     console.error('MySQL connection failed:', err);
//   } else {
//     console.log('Connected to MySQL DB');
//   }
// });
