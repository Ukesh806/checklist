const { Pool } = require('pg');
require('dotenv').config();

// Create PostgreSQL connection pool
const db = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'employee_db',
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test the connection
db.connect((err) => {
    if (err) {
        console.error('PostgreSQL connection failed:', err.message);
        process.exit(1);
    }
    console.log('Connected to PostgreSQL database');
});

module.exports = db;
