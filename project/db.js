const mysql = require('mysql2');
require('dotenv').config();

// Create MySQL connection
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'Uki@12345',
    database: process.env.DB_NAME || 'employee_db'
});

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error('MySQL connection failed: ' + err.message);
        process.exit(1);
    }
    console.log('Connected to MySQL database');
});

module.exports = db;
