const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'public/uploads';
        // Create uploads directory if it doesn't exist
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        // Generate unique filename
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
        // Accept only images
        if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/i)) {
            return cb(new Error('Only image files are allowed!'), false);
        }
        cb(null, true);
    }
});

const app = express();
const port = 5020;
const JWT_SECRET = 'your-secret-key'; // In production, use environment variable

// Serve static files from public directory
app.use(express.static('public'));

// Explicitly serve files from uploads directory
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

// Load environment variables
require('dotenv').config();

// Database configuration
const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
async function testConnection() {
    try {
        const client = await pool.connect();
        console.log('Database connected successfully');
        client.release();
    } catch (error) {
        console.error('Database connection failed:', error);
        process.exit(1);
    }
}

// Create database tables if they don't exist
async function createTablesIfNotExist() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Create questions table
        await client.query(`
            CREATE TABLE IF NOT EXISTS questions (
                id SERIAL PRIMARY KEY,
                question TEXT NOT NULL,
                branch VARCHAR(255) NOT NULL,
                shift VARCHAR(50) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Questions table created or exists');

        // Create checklists table
        await client.query(`
            CREATE TABLE IF NOT EXISTS checklists (
                id VARCHAR(255) PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                branch VARCHAR(255) NOT NULL,
                shift VARCHAR(50) NOT NULL,
                date TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Checklists table created or exists');

        // Create checklist_responses table
        await client.query(`
            CREATE TABLE IF NOT EXISTS checklist_responses (
                id SERIAL PRIMARY KEY,
                checklist_id VARCHAR(255) REFERENCES checklists(id),
                question TEXT NOT NULL,
                answer VARCHAR(50) NOT NULL,
                notes TEXT,
                has_image BOOLEAN DEFAULT FALSE,
                image_data TEXT
            )
        `);
        console.log('Checklist responses table created or exists');

        await client.query('COMMIT');

        // First, create the database if it doesn't exist
        connection = await mysql.createConnection({
            host: dbConfig.host,
            user: dbConfig.user,
            password: dbConfig.password
        });

        await connection.query(`CREATE DATABASE IF NOT EXISTS ${dbConfig.database}`);
        console.log('Database created or already exists');
        await connection.end();

        // Now connect to the database and create tables
        connection = await pool.getConnection();
        console.log('Connected to database, creating tables...');

        // Drop foreign key constraints first
        try {
            await connection.query('ALTER TABLE branch_updates DROP FOREIGN KEY branch_updates_ibfk_1');
        } catch (error) {
            console.log('No branch_updates foreign key constraint to drop');
        }

        await connection.query(`
            CREATE TABLE IF NOT EXISTS employees (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'user',
                branchname VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Employees table created or already exists');

        // Create branch_updates table if it doesn't exist
        await connection.query(`
            CREATE TABLE IF NOT EXISTS branch_updates (
                id INT PRIMARY KEY AUTO_INCREMENT,
                branch_name VARCHAR(100) NOT NULL,
                department_name VARCHAR(100) NOT NULL,
                details TEXT NOT NULL,
                image_path VARCHAR(255),
                created_by INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES employees(id)
            )
        `);
        console.log('Branch updates table created or already exists');

        // Create responses table if it doesn't exist
        await connection.query(`
            CREATE TABLE IF NOT EXISTS responses (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id INT,
                question_id VARCHAR(255),
                question_text TEXT,
                question_type VARCHAR(50),
                mcq_status VARCHAR(50),
                answer_text TEXT,
                shift VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (employee_id) REFERENCES employees(id)
            )
        `);
        console.log('Responses table created successfully');

        connection.release();
        console.log('All tables created successfully');
    } catch (error) {
        console.error('Error creating tables:', error);
        if (connection) {
            connection.release();
        }
        throw error;
    }
}

// Create default admin user if not exists
async function createAdminUser() {
    let connection;
    try {
        connection = await pool.getConnection();

        // Check if admin exists
        console.log('Checking for existing admin user...');
        const [admins] = await connection.query('SELECT id FROM employees WHERE role = ?', ['admin']);
        console.log('Found', admins.length, 'admin users');

        if (admins.length === 0) {
            console.log('No admin user found, creating one...');
            // Create admin user
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await connection.query(
                'INSERT INTO employees (username, password, role, branchname) VALUES (?, ?, ?, ?)',
                ['admin', hashedPassword, 'admin', 'HQ']
            );
            console.log('Admin user created successfully');

            // Verify admin was created
            const [verifyAdmin] = await connection.query('SELECT id, username, role FROM employees WHERE role = ?', ['admin']);
            console.log('Verified admin user:', verifyAdmin);
        } else {
            console.log('Admin user already exists');
        }
    } catch (error) {
        console.error('Error creating admin user:', error);
        throw error; // Re-throw to handle it in the initialization
    } finally {
        if (connection) connection.release();
    }
}

// Initialize the application
async function initializeApp() {
    // Call createTablesIfNotExist on startup
    await createTablesIfNotExist();

    // Create admin user
    await createAdminUser();

    // Test connection on startup
    await testConnection();

    // Get response stats
    app.get('/api/responses/stats', verifyToken, async (req, res) => {
        try {
            const checklists = JSON.parse(fs.readFileSync('checklists.json', 'utf8'));
            
            // Calculate stats
            const stats = {
                totalResponses: 0,
                yesCount: 0,
                noCount: 0,
                pendingCount: 0
            };

            checklists.forEach(checklist => {
                if (checklist.responses) {
                    checklist.responses.forEach(response => {
                        stats.totalResponses++;
                        if (response.answer === 'yes') stats.yesCount++;
                        else if (response.answer === 'no') stats.noCount++;
                        else stats.pendingCount++;
                    });
                }
            });

            res.json(stats);
        } catch (error) {
            console.error('Error getting stats:', error);
            res.status(500).json({ error: 'Failed to get response stats' });
        }
    });

    // Start the server
    app.listen(port, () => {
        console.log(`Server is running on port ${port}`);
    });
}

// Run initialization
initializeApp().catch(error => {
    console.error('Failed to initialize app:', error);
    process.exit(1);
});

// Middleware
app.use(cors({
    origin: 'http://localhost:5090',
    credentials: true
}));
app.use(express.json({ limit: '2mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static('public/uploads'));

// Root path redirects to login
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

// Serve login page
app.get('/login', (req, res) => {
    res.redirect('/login.html');
});

// Serve index page
app.get('/index', (req, res) => {
    res.redirect('/index.html');
});

// Serve employee page
app.get('/employee', (req, res) => {
    res.redirect('/employee.html');
});

// Serve checklist page
app.get('/checklist', (req, res) => {
    res.redirect('/checklist.html');
});

// Serve question generator page
app.get('/question-generate', (req, res) => {
    res.redirect('/question-generate.html');
});

// Verify JWT token middleware
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'Access token is required' 
        });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid or expired token' 
            });
        }
        req.user = decoded;
        next();
    });
};

// Check authentication status
app.get('/api/check-auth', verifyToken, (req, res) => {
    res.json({
        success: true,
        user: {
            id: req.user.id,
            username: req.user.username,
            role: req.user.role,
            branchname: req.user.branchname
        }
    });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    let connection;
    try {
        const { username, password } = req.body;
        
        // Validate input
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // Trim whitespace and convert to lowercase
        const cleanUsername = username.trim().toLowerCase();
        
        // Log login attempt
        console.log('Login attempt:', {
            username: cleanUsername,
            userAgent: req.headers['user-agent'] || 'unknown',
            timestamp: new Date().toISOString()
        });

        // Get database connection
        connection = await pool.getConnection();
        
        // Get user with case-insensitive username comparison
        const { rows } = await pool.query(
            'SELECT * FROM employees WHERE username = $1',
            [username]
        );

        if (rows.length === 0) {
            console.log('User not found:', username);
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        const user = rows[0];
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            console.log('Invalid password for user:', username);
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }
        console.log('Password validation successful for user:', username);

        // Create token with user info
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                role: user.role,
                branchname: user.branchname
            },
            JWT_SECRET,
            { 
                expiresIn: '30d'
            }
        );

        // Send response
        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                branchname: user.branchname
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed',
            error: error.message
        });
    } finally {
        if (connection) {
            console.log('Releasing database connection');
            connection.release();
        }
    }
});

// Add new employee
app.post('/api/employees', verifyToken, async (req, res) => {
    try {
        const { username, password, role, branchname } = req.body;

        // Validate input
        if (!username || !password || !role || !branchname) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }

        // Check if user has permission
        if (req.user.role !== 'admin' && req.user.role !== 'management') {
            return res.status(403).json({ success: false, message: 'Unauthorized to add employees' });
        }

        // Management users can only add regular users
        if (req.user.role === 'management' && role !== 'user') {
            return res.status(403).json({ success: false, message: 'Management users can only add regular users' });
        }

        // Check if username already exists
        let connection;
        connection = await pool.getConnection();
        const [existingUser] = await connection.query(
            'SELECT id FROM employees WHERE username = ?',
            [username]
        );

        if (existingUser.length > 0) {
            connection.release();
            return res.status(400).json({ success: false, message: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new employee
        await pool.query(
            'INSERT INTO employees (username, password, role, branchname) VALUES ($1, $2, $3, $4)',
            [username, hashedPassword, role, branchname]
        );
        res.json({ success: true, message: 'Employee added successfully' });
    } catch (error) {
        console.error('Error adding employee:', error);
        res.status(500).json({ success: false, message: 'Error adding employee' });
    }
});

// Get all employees
app.get('/api/employees', verifyToken, async (req, res) => {
    try {
        let query = 'SELECT id, username, role, branchname, created_at FROM employees';
        
        // If management user, only show regular users
        if (req.user.role === 'management') {
            query += " WHERE role = 'user'";
        }

        let connection;
        connection = await pool.getConnection();
        const [employees] = await connection.query(query);
        connection.release();
        res.json({ success: true, employees });
    } catch (error) {
        console.error('Error getting employees:', error);
        res.status(500).json({ success: false, message: 'Error getting employees' });
    }
});

// Delete employee
app.delete('/api/employees/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        // Check if user has permission
        if (req.user.role !== 'admin' && req.user.role !== 'management') {
            return res.status(403).json({ success: false, message: 'Unauthorized to delete employees' });
        }

        // Get employee details
        let connection;
        connection = await pool.getConnection();
        const [employee] = await connection.query(
            'SELECT role FROM employees WHERE id = ?',
            [id]
        );

        if (employee.length === 0) {
            connection.release();
            return res.status(404).json({ success: false, message: 'Employee not found' });
        }

        // Management users can only delete regular users
        if (req.user.role === 'management' && employee[0].role !== 'user') {
            connection.release();
            return res.status(403).json({ success: false, message: 'Management users can only delete regular users' });
        }

        await connection.query(
            'DELETE FROM employees WHERE id = ?',
            [id]
        );
        connection.release();
        res.json({ success: true, message: 'Employee deleted successfully' });
    } catch (error) {
        console.error('Error deleting employee:', error);
        res.status(500).json({ success: false, message: 'Error deleting employee' });
    }
});

// Get checklist questions
app.get('/api/checklist/questions', verifyToken, async (req, res) => {
    try {
        let connection;
        connection = await pool.getConnection();
        const [rows] = await connection.query(`
            SELECT id, section, question_text as question, question_type as type
            FROM checklist_questions
            ORDER BY section, id
        `);
        connection.release();
        res.json({
            success: true,
            questions: rows
        });
    } catch (error) {
        console.error('Error fetching questions:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch questions',
            error: error.message
        });
    }
});

// Submit checklist responses
app.post('/api/checklist/submit', verifyToken, express.json(), async (req, res) => {
    let connection;
    try {
        // Add detailed request logging
        console.log('=== START OF REQUEST LOGGING ===');
        console.log('Headers:', JSON.stringify(req.headers, null, 2));
        console.log('Body:', JSON.stringify(req.body, null, 2));
        console.log('Files:', JSON.stringify(req.files?.map(f => ({ 
            fieldname: f.fieldname, 
            originalname: f.originalname,
            size: f.size 
        })), null, 2));

        // Check for responses in request body
        if (!req.body || !req.body.responses) {
            return res.status(400).json({
                success: false,
                message: 'No responses data provided in request'
            });
        }

        // Get database connection
        try {
            connection = await pool.getConnection();
            console.log('Database connection established');
        } catch (dbError) {
            console.error('Database connection error:', dbError);
            return res.status(500).json({
                success: false,
                message: 'Database connection failed',
                error: dbError.message
            });
        }

        await connection.beginTransaction();
        console.log('Transaction started');

        const employeeId = req.user.id;
        const currentTime = new Date();
        
        // Parse responses with error handling
        let responses;
        try {
            responses = typeof req.body.responses === 'string' 
                ? JSON.parse(req.body.responses) 
                : req.body.responses;
            console.log('Parsed responses:', JSON.stringify(responses, null, 2));
        } catch (parseError) {
            console.error('Error parsing responses:', parseError);
            return res.status(400).json({
                success: false,
                message: 'Invalid responses format',
                error: parseError.message
            });
        }

        // Get employee details
        let employeeDetails;
        try {
            [employeeDetails] = await connection.query(
                'SELECT username, branchname FROM employees WHERE id = ?',
                [employeeId]
            );
            console.log('Employee details retrieved:', employeeDetails);
        } catch (empError) {
            console.error('Error fetching employee details:', empError);
            throw new Error('Failed to fetch employee details');
        }

        if (!employeeDetails || employeeDetails.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Employee not found'
            });
        }

        const { username, branchname } = employeeDetails[0];

        // Validate responses is an array
        if (!Array.isArray(responses)) {
            return res.status(400).json({
                success: false,
                message: 'Responses must be an array',
                received: typeof responses
            });
        }

        // Validate responses array is not empty
        if (responses.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No responses provided'
            });
        }

        console.log('Starting to insert responses...');

        // Insert each response
        for (const response of responses) {
            try {
                // Validate required fields
                if (!response.question_id || !response.type || !response.question_text) {
                    throw new Error('Missing required fields in response');
                }

                // Find image if exists
                const imagePath = req.files && req.files.find(f => f.fieldname === `image_${response.question_id}`) 
                    ? `/uploads/${req.files.find(f => f.fieldname === `image_${response.question_id}`).filename}`
                    : null;

                // Insert response with proper error handling
                await connection.query(
                    `INSERT INTO checklist_responses (
                        employee_id,
                        username,
                        branchname,
                        question_id,
                        question_text,
                        question_type,
                        mcq_status,
                        answer_text,
                        image_path,
                        submitted_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        employeeId,
                        username,
                        branchname,
                        response.question_id,
                        response.question_text.trim(),
                        response.type,
                        response.type === 'mcq' ? response.status : null,
                        response.type === 'text' ? response.answer : null,
                        imagePath,
                        currentTime
                    ]
                );
                console.log(`Response inserted for question ${response.question_id}`);
            } catch (insertError) {
                console.error('Error inserting response:', insertError);
                throw new Error(`Failed to insert response for question ${response.question_id}: ${insertError.message}`);
            }
        }

        console.log('All responses inserted successfully');
        await connection.commit();
        console.log('Transaction committed');

        res.json({
            success: true,
            message: 'Responses submitted successfully',
            timestamp: currentTime
        });
    } catch (error) {
        console.error('Error in checklist submission:', error);
        if (connection) {
            try {
                await connection.rollback();
                console.log('Transaction rolled back');
            } catch (rollbackError) {
                console.error('Error rolling back transaction:', rollbackError);
            }
        }
        res.status(500).json({
            success: false,
            message: error.message || 'Failed to submit responses',
            details: error.toString()
        });
    } finally {
        if (connection) {
            connection.release();
            console.log('Database connection released');
        }
        console.log('=== END OF REQUEST LOGGING ===');
    }
});

// Get latest checklist responses (admin only)
app.get('/api/checklist/latest', verifyToken, async (req, res) => {
    try {
        // Check if user exists and is admin
        let connection;
        connection = await pool.getConnection();
        const [userRows] = await connection.query(
            'SELECT role FROM employees WHERE username = ?',
            [req.user.username]
        );

        if (!userRows || userRows.length === 0) {
            connection.release();
            return res.status(403).json({
                success: false,
                message: 'User not found'
            });
        }

        const isAdmin = userRows[0].role === 'admin';
        if (!isAdmin) {
            connection.release();
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        // Get latest responses with question and employee details
        const [responses] = await connection.query(`
            SELECT 
                cr.id,
                cr.question_id,
                cr.employee_id,
                cr.answer_text as answer,
                cr.mcq_status as status,
                cr.submitted_at as time,
                cq.question_text as question,
                cq.section,
                cq.question_type as type,
                e.username as employee_name,
                e.branchname as employee_branch,
                cr.image_path as image_path
            FROM checklist_responses cr
            JOIN checklist_questions cq ON cr.question_id = cq.id
            JOIN employees e ON cr.employee_id = e.id
            WHERE cr.id IN (
                SELECT MAX(id)
                FROM checklist_responses
                GROUP BY question_id, employee_id
            )
            ORDER BY cr.submitted_at DESC
        `);
        connection.release();
        // Initialize response objects
        const byStatus = {
            yes: [],
            no: [],
            pending: []
        };

        const writtenResponses = {
            Kitchen: [],
            Cafe: []
        };

        // Process each response
        responses.forEach(row => {
            const response = {
                id: row.id,
                question_id: row.question_id,
                employee_id: row.employee_id,
                status: row.status?.toLowerCase() || 'pending',
                answer: row.answer || '',
                time: row.time,
                question: row.question,
                section: row.section,
                type: row.type,
                employee: row.employee_name,
                branch: row.employee_branch,
                image_path: row.image_path
            };

            if (row.type === 'written') {
                writtenResponses[row.section].push(response);
            } else {
                byStatus[response.status || 'pending'].push(response);
            }
        });

        res.json({
            success: true,
            byStatus,
            writtenResponses
        });
    } catch (error) {
        console.error('Error fetching latest responses:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch responses',
            error: error.message
        });
    }
});

// Delete response (admin only)
app.delete('/api/checklist/response/:id', verifyToken, async (req, res) => {
    try {
        // Check if user is admin
        let connection;
        connection = await pool.getConnection();
        const [userRows] = await connection.query(
            'SELECT role FROM employees WHERE username = ?',
            [req.user.username]
        );

        if (!userRows || userRows.length === 0 || userRows[0].role !== 'admin') {
            connection.release();
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        const responseId = req.params.id;
        await connection.query('DELETE FROM checklist_responses WHERE id = ?', [responseId]);
        connection.release();
        res.json({
            success: true,
            message: 'Response deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting response:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete response',
            error: error.message
        });
    }
});

// Get checklist responses
app.get('/api/checklist/responses', verifyToken, async (req, res) => {
    try {
        let connection;
        try {
            connection = await pool.getConnection();
            
            let query = `
                SELECT 
                    cr.id,
                    cr.submitted_at as created_at,
                    cr.mcq_status as status,
                    e.username,
                    e.branchname as branch,
                    JSON_ARRAYAGG(
                        JSON_OBJECT(
                            'question', cq.question_text,
                            'response', COALESCE(cr.mcq_status, cr.answer_text)
                        )
                    ) as answers,
                    cr.image_path as image_path
                FROM checklist_responses cr
                JOIN employees e ON cr.employee_id = e.id
                JOIN checklist_questions cq ON cr.question_id = cq.id
                WHERE 1=1
            `;
            
            const params = [];
            
            if (req.query.branch) {
                query += ' AND e.branchname = ?';
                params.push(req.query.branch);
            }
            
            if (req.query.date) {
                query += ' AND DATE(cr.submitted_at) = ?';
                params.push(req.query.date);
            }
            
            if (req.query.responseType) {
                query += ' AND cr.mcq_status = ?';
                params.push(req.query.responseType);
            }
            
            query += ' GROUP BY cr.id, cr.submitted_at, cr.mcq_status, e.username, e.branchname, cr.image_path';
            query += ' ORDER BY cr.submitted_at DESC';
            
            const [responses] = await connection.query(query, params);
            
            // Parse the answers JSON for each response
            responses.forEach(response => {
                if (typeof response.answers === 'string') {
                    response.answers = JSON.parse(response.answers);
                }
            });
            
            res.json({ responses });
            
        } finally {
            if (connection) connection.release();
        }
    } catch (error) {
        console.error('Error getting checklist responses:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get checklist statistics
app.get('/api/checklist/stats', verifyToken, async (req, res) => {
    try {
        let connection;
        try {
            connection = await pool.getConnection();
            
            const today = new Date().toISOString().split('T')[0];
            
            const [stats] = await connection.query(`
                SELECT
                    (SELECT COUNT(DISTINCT id) FROM checklist_responses) as totalChecklists,
                    (SELECT COUNT(DISTINCT id) FROM checklist_responses WHERE mcq_status = 'yes') as completedChecklists,
                    (SELECT COUNT(DISTINCT id) FROM checklist_responses WHERE DATE(submitted_at) = ?) as todayUpdates,
                    (SELECT COUNT(DISTINCT id) FROM checklist_responses WHERE mcq_status = 'yes') as yesResponses,
                    (SELECT COUNT(DISTINCT id) FROM checklist_responses WHERE mcq_status = 'no') as noResponses,
                    (SELECT COUNT(DISTINCT id) FROM checklist_responses WHERE mcq_status = 'pending') as pendingResponses,
                    (SELECT COUNT(DISTINCT id) FROM checklist_responses WHERE mcq_status IS NOT NULL) as allResponses
            `, [today]);
            
            res.json(stats[0]);
            
        } finally {
            if (connection) connection.release();
        }
    } catch (error) {
        console.error('Error getting checklist stats:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get branches
app.get('/api/branches', verifyToken, async (req, res) => {
    try {
        let connection;
        try {
            connection = await pool.getConnection();
            
            const [branches] = await connection.query(`
                SELECT DISTINCT branchname as name
                FROM employees
                ORDER BY branchname
            `);
            
            res.json({ branches });
            
        } finally {
            if (connection) connection.release();
        }
    } catch (error) {
        console.error('Error getting branches:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all branches
app.get('/api/branches', verifyToken, async (req, res) => {
    try {
        const query = `SELECT DISTINCT branchname FROM employees`;
        const result = await pool.query(query);
        res.json({ branches: result.rows.map(row => row.branchname) });
    } catch (error) {
        console.error('Error getting branches:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get response statistics
app.get('/api/responses/stats', verifyToken, async (req, res) => {
    try {
        // Get total branches (from employees)
        const branchesQuery = `SELECT COUNT(DISTINCT branchname) as total FROM employees`;
        const branchesResult = await pool.query(branchesQuery);
        
        // Get completed checklists
        const completedQuery = `SELECT COUNT(DISTINCT branchname) as total FROM checklist_responses WHERE DATE(submitted_at) <= $1`;
        const completedResult = await pool.query(completedQuery, [today]);
        
        // Get today's updates
        const todayQuery = `SELECT COUNT(DISTINCT branchname) as total FROM checklist_responses WHERE DATE(submitted_at) = $1`;
        const todayResult = await pool.query(todayQuery, [today]);
        
        // Get response counts by type
        const statusQuery = `
            SELECT 
                mcq_status,
                COUNT(*) as count
            FROM checklist_responses 
            WHERE mcq_status IS NOT NULL
            GROUP BY mcq_status`;
        const statusResult = await pool.query(statusQuery);
        
        // Get total responses
        const totalResponsesQuery = `SELECT COUNT(*) as total FROM checklist_responses`;
        const totalResult = await pool.query(totalResponsesQuery);
        
        const stats = {
            totalBranches: branchesResult.rows[0].total,
            completedChecklists: completedResult.rows[0].total,
            todayUpdates: todayResult.rows[0].total,
            yes: 0,
            no: 0,
            pending: 0,
            totalResponses: totalResult.rows[0].total
        };
        
        statusResult.rows.forEach(row => {
            if (row.mcq_status === 'yes') stats.yes = parseInt(row.count);
            if (row.mcq_status === 'no') stats.no = parseInt(row.count);
            if (row.mcq_status === 'pending') stats.pending = parseInt(row.count);
        });
        
        res.json(stats);
    } catch (error) {
        console.error('Error getting response stats:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get detailed responses by type
app.get('/api/responses/details/:type', verifyToken, async (req, res) => {
    try {
        const { type } = req.params;
        let query = '';
        const params = [];

        switch (type) {
            case 'total-branches':
                query = `SELECT DISTINCT branchname FROM employees ORDER BY branchname`;
                break;

            case 'completed-checklists':
                query = `
                    SELECT DISTINCT r.branchname 
                    FROM checklist_responses r 
                    WHERE DATE(r.created_at) = CURDATE()
                    ORDER BY r.branchname
                `;
                break;

            case 'today-updates':
                query = `
                    SELECT DISTINCT r.branchname 
                    FROM checklist_responses r 
                    WHERE DATE(r.created_at) = CURDATE()
                    ORDER BY r.branchname
                `;
                break;

            case 'yes':
            case 'no':
            case 'pending':
                query = `
                    SELECT 
                        r.id,
                        r.branchname,
                        r.username,
                        r.question_text,
                        r.mcq_status,
                        DATE_FORMAT(r.created_at, '%Y-%m-%d %H:%i:%s') as formatted_date,
                        r.image_path as image_path
                    FROM checklist_responses r
                    WHERE r.mcq_status = ?
                    ORDER BY r.created_at DESC
                `;
                params.push(type);
                break;

            case 'all':
                query = `
                    SELECT 
                        r.id,
                        r.branchname,
                        r.username,
                        r.question_text,
                        r.mcq_status,
                        DATE_FORMAT(r.created_at, '%Y-%m-%d %H:%i:%s') as formatted_date,
                        r.image_path as image_path
                    FROM checklist_responses r
                    ORDER BY r.created_at DESC
                `;
                break;

            default:
                return res.status(400).json({ error: 'Invalid type' });
        }

        const [rows] = await pool.query(query, params);
        res.json({ responses: rows });
    } catch (error) {
        console.error('Error getting response details:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all responses with filters
app.get('/api/responses', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const { branch, status, fromDate, toDate } = req.query;
        
        // Create table if it doesn't exist
        await createTablesIfNotExist();

        let query = `
            SELECT DISTINCT
                r.id,
                r.employee_id,
                e.username,
                e.branchname,
                r.question_id,
                r.question_text,
                r.question_type,
                r.mcq_status,
                r.answer_text,
                DATE_FORMAT(r.submitted_at, '%Y-%m-%d %H:%i:%s') as formatted_date,
                r.image_path
            FROM checklist_responses r
            RIGHT JOIN employees e ON r.employee_id = e.id
            WHERE DATE(r.submitted_at) = CURDATE() OR r.submitted_at IS NULL
        `;
        
        const params = [];

        if (branch) {
            query += ` AND e.branchname = ?`;
            params.push(branch);
        }

        if (status) {
            query += ` AND r.mcq_status = ?`;
            params.push(status);
        }

        query += ` ORDER BY r.submitted_at DESC`;

        const [responses] = await connection.query(query, params);
        const [branches] = await connection.query('SELECT DISTINCT branchname FROM employees WHERE branchname IS NOT NULL ORDER BY branchname');

        res.json({
            success: true,
            responses: responses.filter(r => r.id !== null), // Filter out null responses
            branches: branches.map(b => b.branchname)
        });
    } catch (error) {
        console.error('Error loading responses:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load responses',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get response statistics
app.get('/api/responses/stats', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const today = new Date().toISOString().split('T')[0];

        // Create table if it doesn't exist
        await createTablesIfNotExist();

        // Get total branches
        const [totalBranches] = await connection.query(
            'SELECT COUNT(DISTINCT branchname) as count FROM employees WHERE branchname IS NOT NULL'
        );

        // Get completed branches today
        const [completedToday] = await connection.query(
            `SELECT COUNT(DISTINCT e.branchname) as count
             FROM checklist_responses r
             JOIN employees e ON r.employee_id = e.id
             WHERE DATE(r.submitted_at) = CURDATE()`
        );

        // Get response counts by status
        const [statusCounts] = await connection.query(
            `SELECT 
                mcq_status,
                COUNT(*) as count
             FROM checklist_responses
             WHERE DATE(submitted_at) = CURDATE()
             GROUP BY mcq_status`
        );

        // Convert status counts to object
        const counts = {
            yes: 0,
            no: 0,
            pending: 0
        };
        statusCounts.forEach(row => {
            if (row.mcq_status in counts) {
                counts[row.mcq_status] = row.count;
            }
        });

        res.json({
            success: true,
            totalBranches: totalBranches[0].count,
            completedToday: completedToday[0].count || 0,
            pendingToday: totalBranches[0].count - (completedToday[0].count || 0),
            yesCount: counts.yes,
            noCount: counts.no,
            pendingCount: counts.pending
        });
    } catch (error) {
        console.error('Error getting response stats:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch stats',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get missing branches (branches that haven't submitted today)
app.get('/api/responses/missing-branches', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();

        // Create table if it doesn't exist
        await createTablesIfNotExist();
        
        // Get all branches
        const [allBranches] = await connection.query(
            'SELECT DISTINCT branchname FROM employees WHERE branchname IS NOT NULL ORDER BY branchname'
        );

        // Get branches that have submitted today
        const [submittedBranches] = await connection.query(
            `SELECT DISTINCT e.branchname 
             FROM checklist_responses r
             JOIN employees e ON r.employee_id = e.id
             WHERE DATE(r.submitted_at) = CURDATE()`
        );

        // Convert submitted branches to a Set for faster lookup
        const submittedSet = new Set(submittedBranches.map(b => b.branchname));

        // Filter out branches that have already submitted
        const missingBranches = allBranches
            .filter(b => !submittedSet.has(b.branchname))
            .map(b => b.branchname);

        res.json({
            success: true,
            branches: missingBranches
        });
    } catch (error) {
        console.error('Error getting missing branches:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve missing branches',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get completed branches (branches that have submitted today)
app.get('/api/responses/completed-branches', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();

        // Create table if it doesn't exist
        await createTablesIfNotExist();
        
        // Get branches that have submitted today
        const [completedBranches] = await connection.query(
            `SELECT DISTINCT 
                e.branchname as name,
                MAX(r.submitted_at) as lastSubmission
             FROM checklist_responses r
             JOIN employees e ON r.employee_id = e.id
             WHERE DATE(r.submitted_at) = CURDATE()
             GROUP BY e.branchname
             ORDER BY lastSubmission DESC`
        );

        res.json({
            success: true,
            branches: completedBranches
        });
    } catch (error) {
        console.error('Error getting completed branches:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch completed branches',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get today's updates by branch
app.get('/api/responses/today-updates', verifyToken, async (req, res) => {
    try {
        const query = `
            SELECT 
                branchname,
                COUNT(*) as update_count
            FROM checklist_responses 
            WHERE DATE(submitted_at) = CURDATE()
            GROUP BY branchname
            ORDER BY branchname
        `;
        
        const [updates] = await pool.query(query);
        res.json({ updates });
    } catch (error) {
        console.error('Error getting today updates:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get responses by status
app.get('/api/responses/by-status/:status', verifyToken, async (req, res) => {
    try {
        const { status } = req.params;
        const query = `
            SELECT 
                r.id,
                r.branchname,
                r.username,
                r.question_text,
                r.mcq_status,
                DATE_FORMAT(r.submitted_at, '%Y-%m-%d %H:%i:%s') as formatted_date,
                r.image_path as image_path
            FROM checklist_responses r
            WHERE r.mcq_status = ?
            ORDER BY r.submitted_at DESC
        `;
        
        const [responses] = await pool.query(query, [status]);
        res.json({ responses });
    } catch (error) {
        console.error('Error getting responses by status:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get response counts
app.get('/api/responses/counts', verifyToken, async (req, res) => {
    try {
        const query = `
            SELECT 
                SUM(CASE WHEN mcq_status = 'yes' THEN 1 ELSE 0 END) as yes_count,
                SUM(CASE WHEN mcq_status = 'no' THEN 1 ELSE 0 END) as no_count,
                SUM(CASE WHEN mcq_status = 'pending' THEN 1 ELSE 0 END) as pending_count
            FROM checklist_responses
            WHERE DATE(submitted_at) = CURDATE()
        `;
        
        const [counts] = await pool.query(query);
        
        res.json({
            yes: counts[0].yes_count || 0,
            no: counts[0].no_count || 0,
            pending: counts[0].pending_count || 0
        });
    } catch (error) {
        console.error('Error getting response counts:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get completed checklist branches with counts
app.get('/api/responses/completed-branches', verifyToken, async (req, res) => {
    try {
        const query = `
            SELECT 
                r.branchname,
                COUNT(*) as response_count
            FROM checklist_responses r
            WHERE 
                r.mcq_status = 'yes' 
                AND DATE(r.submitted_at) = CURDATE()
            GROUP BY r.branchname
            ORDER BY r.branchname ASC
        `;
        
        const [rows] = await pool.query(query);
        res.json({ branches: rows });
    } catch (error) {
        console.error('Error getting completed branches:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Branch updates endpoint
app.post('/api/branch-updates', verifyToken, upload.single('image'), async (req, res) => {
    let connection;
    try {
        const { branch_name, department_name, details } = req.body;
        
        // Validate required fields
        if (!branch_name || !department_name || !details) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }

        connection = await pool.getConnection();
        
        // Insert the update with image path if present
        const [result] = await connection.query(
            'INSERT INTO branch_updates (branch_name, department_name, details, image_path, created_by) VALUES (?, ?, ?, ?, ?)',
            [branch_name, department_name, details, req.file ? `/uploads/${req.file.filename}` : null, req.user.id]
        );

        // Get the inserted update with formatted image path
        const [newUpdates] = await connection.query(
            'SELECT *, ? as base_url FROM branch_updates WHERE id = ?',
            [`http://localhost:${port}`, result.insertId]
        );

        // Format the response
        const formattedUpdate = {
            ...newUpdates[0],
            image_path: newUpdates[0].image_path ? 
                `http://localhost:${port}${newUpdates[0].image_path}` : null
        };

        res.json({
            success: true,
            message: 'Update added successfully',
            update: formattedUpdate
        });
    } catch (error) {
        console.error('Error adding branch update:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add update',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get branch updates
app.get('/api/branch-updates', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        
        // Get all updates with formatted image paths
        const [updates] = await connection.query(
            'SELECT *, ? as base_url FROM branch_updates ORDER BY created_at DESC',
            [`http://localhost:${port}`]
        );

        // Format image paths
        const formattedUpdates = updates.map(update => ({
            ...update,
            image_path: update.image_path ? 
                `http://localhost:${port}${update.image_path}` : null
        }));

        res.json({
            success: true,
            updates: formattedUpdates
        });
    } catch (error) {
        console.error('Error getting branch updates:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get updates',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get completed checklist branches with all their data
app.get('/api/responses/completed-branches', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        
        // Get all completed checklists grouped by branch
        const query = `
            SELECT 
                r.branchname,
                COUNT(*) as total_responses,
                MAX(DATE(r.submitted_at)) as last_submission_date,
                GROUP_CONCAT(DISTINCT DATE(r.submitted_at) ORDER BY r.submitted_at DESC) as submission_dates,
                (
                    SELECT COUNT(*)
                    FROM checklist_responses r2
                    WHERE r2.branchname = r.branchname
                    AND DATE(r2.submitted_at) = CURDATE()
                    AND r2.mcq_status = 'yes'
                ) as today_responses
            FROM checklist_responses r
            WHERE r.mcq_status = 'yes'
            GROUP BY r.branchname
            ORDER BY 
                today_responses DESC,
                last_submission_date DESC,
                r.branchname ASC
        `;
        
        // Get total branches count
        const [totalCount] = await connection.query(
            'SELECT COUNT(DISTINCT branchname) as count FROM employees'
        );
        
        // Get branches that completed today
        const [todayCount] = await connection.query(`
            SELECT COUNT(DISTINCT branchname) as count 
            FROM checklist_responses 
            WHERE DATE(submitted_at) = CURDATE() 
            AND mcq_status = 'yes'
        `);
        
        // Process the data to include submission history
        const [branches] = await connection.query(query);
        const processedBranches = branches.map(branch => ({
            ...branch,
            submission_dates: branch.submission_dates ? branch.submission_dates.split(',') : [],
            has_submitted_today: branch.today_responses > 0
        }));
        
        const stats = {
            total_branches: totalCount[0].count,
            completed_today: todayCount[0].count,
            total_completed: branches.length
        };
        
        res.json({ 
            branches: processedBranches,
            stats: stats
        });
    } catch (error) {
        console.error('Error getting completed branches:', error);
        res.status(500).json({ 
            error: 'Failed to retrieve completed branches',
            details: error.message 
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Get completed checklist branches
app.get('/api/responses/completed-branches', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        
        // Get all branches that have submitted checklists
        const query = `
            SELECT DISTINCT
                r.branchname,
                COUNT(*) as total_submissions,
                MAX(DATE(r.submitted_at)) as last_submission,
                CASE 
                    WHEN EXISTS (
                        SELECT 1 
                        FROM checklist_responses 
                        WHERE branchname = r.branchname 
                        AND DATE(submitted_at) = CURDATE()
                        AND mcq_status = 'yes'
                    ) THEN 1 
                    ELSE 0 
                END as submitted_today
            FROM checklist_responses r
            WHERE r.mcq_status = 'yes'
            GROUP BY r.branchname
            ORDER BY submitted_today DESC, last_submission DESC;
        `;
        
        const [branches] = await connection.query(query);
        console.log('Completed branches:', branches); // Debug log
        
        res.json({ 
            branches: branches.map(branch => ({
                branchname: branch.branchname,
                total_submissions: branch.total_submissions,
                last_submission: branch.last_submission,
                submitted_today: branch.submitted_today === 1
            }))
        });
    } catch (error) {
        console.error('Error getting completed branches:', error);
        res.status(500).json({ 
            error: 'Failed to retrieve completed branches',
            branches: []
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Get missing branches (branches that haven't submitted today)
app.get('/api/responses/missing-branches', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const today = new Date().toISOString().split('T')[0];

        // Create table if it doesn't exist
        await createTablesIfNotExist();
        
        // Get all branches
        const [allBranches] = await connection.query(
            'SELECT DISTINCT branchname FROM employees WHERE branchname IS NOT NULL'
        );

        // Get branches that have submitted today
        const [submittedBranches] = await connection.query(
            `SELECT DISTINCT e.branchname 
             FROM checklist_responses r
             JOIN employees e ON r.employee_id = e.id
             WHERE DATE(r.submitted_at) = ?`,
            [today]
        );

        // Find branches that haven't submitted
        const submittedSet = new Set(submittedBranches.map(b => b.branchname));
        const missingBranches = allBranches
            .filter(b => !submittedSet.has(b.branchname))
            .map(b => b.branchname);

        res.json({
            success: true,
            branches: missingBranches
        });
    } catch (error) {
        console.error('Error getting missing branches:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve missing branches',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get completed branches (branches that have submitted today)
app.get('/api/responses/completed-branches', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const today = new Date().toISOString().split('T')[0];

        // Create table if it doesn't exist
        await createTablesIfNotExist();
        
        // Get branches that have submitted today with their last submission time
        const [completedBranches] = await connection.query(
            `SELECT DISTINCT 
                e.branchname as name,
                MAX(r.submitted_at) as lastSubmission
             FROM checklist_responses r
             JOIN employees e ON r.employee_id = e.id
             WHERE DATE(r.submitted_at) = ?
             GROUP BY e.branchname
             ORDER BY lastSubmission DESC`
        );

        res.json({
            success: true,
            branches: completedBranches
        });
    } catch (error) {
        console.error('Error getting completed branches:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch completed checklists',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get responses by status
app.get('/api/responses/by-status/:status', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const { status } = req.params;
        const today = new Date().toISOString().split('T')[0];

        const [responses] = await connection.query(
            `SELECT 
                r.*,
                e.username,
                e.branchname
             FROM checklist_responses r
             JOIN employees e ON r.employee_id = e.id
             WHERE r.mcq_status = ? AND DATE(r.submitted_at) = ?
             ORDER BY r.submitted_at DESC`,
            [status, today]
        );

        res.json({
            success: true,
            responses: responses
        });
    } catch (error) {
        console.error('Error getting responses by status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch responses',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get response image
app.get('/api/checklist/image/:responseId', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const { responseId } = req.params;

        const [response] = await connection.query(
            'SELECT image_path FROM checklist_responses WHERE id = ?',
            [responseId]
        );

        if (response.length === 0 || !response[0].image_path) {
            return res.json({
                success: false,
                message: 'No image found'
            });
        }

        res.json({
            success: true,
            imageUrl: response[0].image_path
        });
    } catch (error) {
        console.error('Error getting response image:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch image',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Branch update endpoints
app.post('/api/branch-updates', verifyToken, async (req, res) => {
    let connection;
    try {
        const { branch_name, department_name, details } = req.body;
        if (!branch_name || !department_name || !details) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }

        connection = await pool.getConnection();
        const [result] = await connection.query(
            'INSERT INTO branch_updates (branch_name, department_name, details, image_path, created_by) VALUES (?, ?, ?, ?, ?)',
            [branch_name, department_name, details, req.file ? req.file.filename : null, req.user.id]
        );

        res.json({
            success: true,
            message: 'Branch update created successfully',
            updateId: result.insertId
        });
    } catch (error) {
        console.error('Error creating branch update:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create branch update',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/branch-updates', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [updates] = await connection.query(
            `SELECT bu.*, e.username as created_by_username 
             FROM branch_updates bu 
             JOIN employees e ON bu.created_by = e.id 
             ORDER BY bu.created_at DESC`
        );

        // Format image paths to include full URL
        const formattedUpdates = updates.map(update => ({
            ...update,
            image_path: update.image_path ? `/uploads/${update.image_path}` : null
        }));

        res.json({
            success: true,
            updates: formattedUpdates
        });
    } catch (error) {
        console.error('Error getting branch updates:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch branch updates',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

app.delete('/api/branch-updates/:id', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [result] = await connection.query(
            'DELETE FROM branch_updates WHERE id = ?',
            [req.params.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Branch update not found'
            });
        }

        res.json({
            success: true,
            message: 'Branch update deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting branch update:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete branch update',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Checklist submission endpoint
app.post('/api/checklist/submit', verifyToken, express.json(), async (req, res) => {
    let connection;
    try {
        const { shift, responses } = req.body;
        console.log('Request body:', JSON.stringify(req.body, null, 2));
        console.log('User ID:', req.user.id);

        // Basic validation
        if (!shift || !responses) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: shift and responses are required'
            });
        }

        // Validate shift value
        if (!['morning', 'evening'].includes(shift)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid shift value. Must be "morning" or "evening"'
            });
        }

        // Validate responses array
        if (!Array.isArray(responses) || responses.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Responses must be a non-empty array'
            });
        }

        connection = await pool.getConnection();

        // Create responses table if it doesn't exist
        await connection.query(`
            CREATE TABLE IF NOT EXISTS responses (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id INT NOT NULL,
                question_id INT NOT NULL,
                question_text TEXT,
                question_type VARCHAR(10) NOT NULL,
                mcq_status VARCHAR(10) NOT NULL,
                answer_text TEXT,
                shift VARCHAR(10) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        `);
        console.log('Ensured responses table exists');

        await connection.beginTransaction();

        try {
            const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');

            console.log('Received request body:', req.body);
            console.log('Number of responses:', responses.length);
            console.log('First response sample:', responses[0]);

            // Process each response
            const insertPromises = responses.map(async (response, i) => {
                try {
                    console.log(`\nProcessing response ${i + 1}:`, JSON.stringify(response, null, 2));

                    // Detailed validation
                    if (!response) {
                        throw new Error(`Response ${i + 1} is null or undefined`);
                    }

                    if (typeof response !== 'object') {
                        throw new Error(`Response ${i + 1} is not an object, got ${typeof response}`);
                    }

                    if (!response.question_id) {
                        throw new Error(`Response ${i + 1} is missing question_id`);
                    }

                    if (!response.mcq_status) {
                        throw new Error(`Response ${i + 1} is missing mcq_status`);
                    }

                    // Prepare and validate data
                    const params = [
                        req.user.id,
                        parseInt(response.question_id),
                        response.question_text || '',
                        'mcq',
                        response.mcq_status,
                        response.notes || '',
                        shift,
                        new Date()
                    ];

                    console.log(`Validated params for response ${i + 1}:`, params);

                    // Insert the response
                    await connection.query(`
                        INSERT INTO responses (
                            employee_id, question_id, question_text, question_type,
                            mcq_status, answer_text, shift, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    `, params);

                    console.log(`Successfully inserted response ${i + 1}`);
                    return true;
                } catch (error) {
                    console.error(`Error processing response ${i + 1}:`, error);
                    throw error;
                }
            });

            // Wait for all inserts to complete
            await Promise.all(insertPromises);

            await connection.commit();
            console.log('All responses committed successfully');

            res.json({
                success: true,
                message: 'Checklist submitted successfully'
            });
        } catch (error) {
            console.error('Transaction error:', error);
            await connection.rollback();
            throw error;
        }
    } catch (error) {
        console.error('Error submitting checklist:', error);
        res.status(500).json({
            success: false,
            message: error.message,
            details: error.toString()
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Submit checklist endpoint
app.post('/api/checklists', async (req, res) => {
    let connection;
    try {
        const { id, username, branch, shift, date, responses } = req.body;
        
        // Validate required fields
        if (!id || !username || !branch || !shift || !date || !responses) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }

        connection = await pool.getConnection();
        await connection.beginTransaction();

        // Insert checklist header
        await connection.query(
            'INSERT INTO checklists (id, username, branch, shift, date) VALUES (?, ?, ?, ?, ?)',
            [id, username, branch, shift, new Date(date)]
        );

        // Insert responses
        for (const response of responses) {
            await connection.query(
                'INSERT INTO checklist_responses (checklist_id, question, answer, notes, has_image, image_data) VALUES (?, ?, ?, ?, ?, ?)',
                [id, response.question, response.answer, response.notes || '', response.hasImage, response.imageData]
            );
        }

        await connection.commit();
        res.json({
            success: true,
            message: 'Checklist saved successfully'
        });

    } catch (error) {
        console.error('Error saving checklist:', error);
        if (connection) {
            await connection.rollback();
        }
        res.status(500).json({
            success: false,
            message: 'Failed to save checklist',
            error: error.message
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Submit checklist endpoint
app.post('/api/checklists', async (req, res) => {
    let connection;
    try {
        const { id, username, branch, shift, date, responses } = req.body;

        // Validate required fields
        if (!id || !username || !branch || !shift || !date || !responses) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }

        connection = await pool.getConnection();
        await connection.beginTransaction();

        try {
            // Insert checklist header
            await connection.query(
                'INSERT INTO checklists (id, username, branch, shift, date) VALUES (?, ?, ?, ?, ?)',
                [id, username, branch, shift, new Date(date)]
            );

            // Insert responses
            for (const response of responses) {
                await connection.query(
                    'INSERT INTO checklist_responses (checklist_id, question, answer, notes, has_image, image_data) VALUES (?, ?, ?, ?, ?, ?)',
                    [id, response.question, response.answer, response.notes || '', response.hasImage, response.imageData]
                );
            }

            await connection.commit();
            res.json({
                success: true,
                message: 'Checklist saved successfully'
            });
        } catch (error) {
            await connection.rollback();
            throw error;
        }
    } catch (error) {
        console.error('Error saving checklist:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to save checklist',
            error: error.message
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Get checklists endpoint
app.get('/api/checklists', async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [checklists] = await connection.query(`
            SELECT c.*, 
                   JSON_ARRAYAGG(
                       JSON_OBJECT(
                           'question', r.question,
                           'answer', r.answer,
                           'notes', r.notes,
                           'hasImage', r.has_image,
                           'imageData', r.image_data
                       )
                   ) as responses
            FROM checklists c
            LEFT JOIN checklist_responses r ON c.id = r.checklist_id
            GROUP BY c.id
            ORDER BY c.date DESC
        `);

        res.json(checklists);
    } catch (error) {
        console.error('Error fetching checklists:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch checklists',
            error: error.message
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Get response statistics
app.get('/api/responses/stats', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        // Get response counts for today
        const [results] = await connection.query(`
            SELECT 
                COUNT(*) as totalResponses,
                SUM(CASE WHEN answer = 'yes' THEN 1 ELSE 0 END) as yesResponses,
                SUM(CASE WHEN answer = 'no' THEN 1 ELSE 0 END) as noResponses,
                SUM(CASE WHEN answer = 'pending' THEN 1 ELSE 0 END) as pendingResponses
            FROM checklist_responses cr
            INNER JOIN checklists c ON cr.checklist_id = c.id
            WHERE DATE(c.date) = DATE(?)
        `, [today]);

        const stats = results[0] || {
            totalResponses: 0,
            yesResponses: 0,
            noResponses: 0,
            pendingResponses: 0
        };

        res.json({
            success: true,
            ...stats
        });
    } catch (error) {
        console.error('Error getting response stats:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get response stats',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get branch submission status for today
app.get('/api/responses/branch-status', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        // Get all branches with their submission status
        const [results] = await connection.query(`
            SELECT DISTINCT
                e.branchname,
                CASE 
                    WHEN EXISTS (
                        SELECT 1
                        FROM responses r
                        WHERE r.branch = e.branchname
                        AND DATE(r.submitted_at) = CURDATE()
                    ) THEN 'submitted'
                    ELSE 'pending'
                END as status
            FROM employees e
            WHERE e.role = 'user'
            ORDER BY e.branchname
        `);

        console.log('Query date:', today);
        console.log('Branch status:', results);

        // Separate submitted and pending branches
        const submitted = results.filter(r => r.status === 'submitted').map(r => r.branchname);
        const pending = results.filter(r => r.status === 'pending').map(r => r.branchname);

        res.json({
            success: true,
            submitted,
            pending
        });
    } catch (error) {
        console.error('Error getting branch status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get branch status',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get missing branches (branches that haven't submitted today's checklist)
app.get('/api/responses/missing-branches', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        // Get all branches that haven't submitted a checklist today
        const [results] = await connection.query(`
            SELECT DISTINCT e.branchname
            FROM employees e
            WHERE e.role = 'user'
            AND NOT EXISTS (
                SELECT 1
                FROM checklist_responses cr
                INNER JOIN checklists c ON cr.checklist_id = c.id
                WHERE c.branch = e.branchname
                AND DATE(c.date) = DATE(?)
            )
            ORDER BY e.branchname
        `, [today]);

        console.log('Query date:', today);
        console.log('Missing branches:', results);

        res.json({
            success: true,
            branches: results.map(r => r.branchname)
        });
    } catch (error) {
        console.error('Error getting missing branches:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get missing branches',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Question management routes
app.get('/api/questions', verifyToken, async (req, res) => {
    let connection;
    try {
        const { branch, shift } = req.query;
        connection = await pool.getConnection();
        
        let query = 'SELECT * FROM questions';
        let params = [];
        
        if (branch && shift) {
            query += ' WHERE branch = ? AND shift = ?';
            params = [branch, shift];
        }
        
        query += ' ORDER BY created_at DESC';
        const [questions] = await connection.query(query, params);
        res.json({
            success: true,
            questions: questions.map(q => ({
                question: q.question,
                branch: q.branch,
                shift: q.shift
            }))
        });
    } catch (error) {
        console.error('Error getting questions:', error);
        res.status(500).json({
            success: false,
            message: 'Error getting questions',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/questions', verifyToken, async (req, res) => {
    let connection;
    try {
        const { question, branch, shift } = req.body;
        if (!question || !branch || !shift) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        connection = await pool.getConnection();
        await connection.query(
            'INSERT INTO questions (question, branch, shift) VALUES (?, ?, ?)',
            [question, branch, shift]
        );
        res.json({
            success: true,
            message: 'Question added successfully'
        });
    } catch (error) {
        console.error('Error adding question:', error);
        res.status(500).json({
            success: false,
            message: 'Error adding question',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/questions/:id', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [questions] = await connection.query('SELECT * FROM questions WHERE id = ?', [req.params.id]);
        if (questions.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Question not found'
            });
        }
        res.json({
            success: true,
            question: questions[0]
        });
    } catch (error) {
        console.error('Error getting question:', error);
        res.status(500).json({
            success: false,
            message: 'Error getting question',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/questions/:id', verifyToken, async (req, res) => {
    let connection;
    try {
        const { question, branch, shift } = req.body;
        if (!question || !branch || !shift) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        connection = await pool.getConnection();
        const [result] = await connection.query(
            'UPDATE questions SET question = ?, branch = ?, shift = ? WHERE id = ?',
            [question, branch, shift, req.params.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Question not found'
            });
        }

        res.json({
            success: true,
            message: 'Question updated successfully'
        });
    } catch (error) {
        console.error('Error updating question:', error);
        res.status(500).json({
            success: false,
            message: 'Error updating question',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

app.delete('/api/questions/:id', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [result] = await connection.query('DELETE FROM questions WHERE id = ?', [req.params.id]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Question not found'
            });
        }

        res.json({
            success: true,
            message: 'Question deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting question:', error);
        res.status(500).json({
            success: false,
            message: 'Error deleting question',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get all branches
app.get('/api/branches', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [branches] = await connection.query('SELECT DISTINCT branchname FROM employees WHERE role = "user" ORDER BY branchname');
        res.json({
            success: true,
            branches: branches.map(b => b.branchname)
        });
    } catch (error) {
        console.error('Error getting branches:', error);
        res.status(500).json({
            success: false,
            message: 'Error getting branches',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Submit checklist
app.post('/api/checklists', verifyToken, async (req, res) => {
    let connection;
    try {
        console.log('Received checklist submission request');
        console.log('Request body:', {
            username: req.body.username,
            branch: req.body.branch,
            shift: req.body.shift,
            date: req.body.date,
            responsesPresent: !!req.body.responses,
            responsesLength: req.body.responses ? req.body.responses.length : 0
        });

        if (!req.body) {
            console.error('No request body received');
            return res.status(400).json({
                success: false,
                message: 'No request body received'
            });
        }

        const { username, branch, shift, date, responses } = req.body;

        // Log the extracted values
        console.log('Extracted values:', { username, branch, shift, date, responsesLength: responses ? responses.length : 0 });

        // Detailed validation with specific messages
        if (!username) {
            return res.status(400).json({
                success: false,
                message: 'Username is required'
            });
        }
        if (!branch) {
            return res.status(400).json({
                success: false,
                message: 'Branch is required'
            });
        }
        if (!shift) {
            return res.status(400).json({
                success: false,
                message: 'Shift is required'
            });
        }
        if (!date) {
            return res.status(400).json({
                success: false,
                message: 'Date is required'
            });
        }
        if (!responses) {
            return res.status(400).json({
                success: false,
                message: 'Responses are required'
            });
        }
        if (!Array.isArray(responses)) {
            return res.status(400).json({
                success: false,
                message: 'Responses must be an array'
            });
        }
        if (responses.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'At least one response is required'
            });
        }

        // Validate each response
        for (let i = 0; i < responses.length; i++) {
            const response = responses[i];
            if (!response.question || typeof response.question !== 'string' || response.question.trim().length === 0) {
                return res.status(400).json({
                    success: false,
                    message: `Response ${i + 1} is missing a valid question`
                });
            }
            if (!response.answer || typeof response.answer !== 'string' || !['Yes', 'No'].includes(response.answer)) {
                return res.status(400).json({
                    success: false,
                    message: `Response ${i + 1} must have an answer of 'Yes' or 'No'`
                });
            }
            // Ensure notes is a string
            if (response.notes && typeof response.notes !== 'string') {
                response.notes = String(response.notes);
            }
            // Ensure imageData is either null or a string
            if (response.imageData && typeof response.imageData !== 'string') {
                response.imageData = null;
            }
        }

        connection = await pool.getConnection();

        // Start transaction
        await connection.beginTransaction();

        try {
            // Create checklist entry
            const checklistId = Date.now().toString();
            await connection.query(
                'INSERT INTO checklists (id, username, branch, shift, date) VALUES (?, ?, ?, ?, ?)',
                [checklistId, username, branch, shift, date]
            );

            // Insert responses
            for (const response of responses) {
                const { question, answer, notes, imageData } = response;
                await connection.query(
                    'INSERT INTO checklist_responses (checklist_id, question, answer, notes, has_image, image_data) VALUES (?, ?, ?, ?, ?, ?)',
                    [checklistId, question, answer, notes, !!imageData, imageData]
                );
            }

            // Commit transaction
            await connection.commit();

            res.json({
                success: true,
                message: 'Checklist submitted successfully',
                checklistId
            });
        } catch (error) {
            // Rollback on error
            await connection.rollback();
            throw error;
        }
    } catch (error) {
        console.error('Error submitting checklist:', error);
        res.status(500).json({
            success: false,
            message: 'Error submitting checklist',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get all questions
app.get('/api/questions', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [rows] = await connection.query('SELECT * FROM questions ORDER BY created_at DESC');

        res.json({
            success: true,
            questions: rows
        });
    } catch (error) {
        console.error('Error getting questions:', error);
        res.status(500).json({
            success: false,
            message: 'Error getting questions',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Get a single question by ID
app.get('/api/questions/:id', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [rows] = await connection.query(
            'SELECT * FROM questions WHERE id = ?',
            [req.params.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Question not found'
            });
        }

        res.json({
            success: true,
            question: rows[0]
        });
    } catch (error) {
        console.error('Error getting question:', error);
        res.status(500).json({
            success: false,
            message: 'Error getting question',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Update a question by ID
app.put('/api/questions/:id', verifyToken, async (req, res) => {
    let connection;
    try {
        const { question, branch, shift } = req.body;

        // Validate input
        if (!question || !branch || !shift) {
            return res.status(400).json({
                success: false,
                message: 'Question, branch, and shift are required'
            });
        }

        connection = await pool.getConnection();
        const [result] = await connection.query(
            'UPDATE questions SET question = ?, branch = ?, shift = ? WHERE id = ?',
            [question, branch, shift, req.params.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Question not found'
            });
        }

        res.json({
            success: true,
            message: 'Question updated successfully'
        });
    } catch (error) {
        console.error('Error updating question:', error);
        res.status(500).json({
            success: false,
            message: 'Error updating question',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Delete a question by ID
app.delete('/api/questions/:id', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [result] = await connection.query(
            'DELETE FROM questions WHERE id = ?',
            [req.params.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Question not found'
            });
        }

        res.json({
            success: true,
            message: 'Question deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting question:', error);
        res.status(500).json({
            success: false,
            message: 'Error deleting question',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// Get all employees
app.get('/api/employees', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        let query = 'SELECT id, username, role, branchname, created_at FROM employees';
        let params = [];
        
        // If user is management, only show regular users
        if (req.user.role === 'management') {
            query += " WHERE role = 'user'";
        }
        // If user is branch manager, only show users from their branch
        else if (req.user.role === 'branch_manager') {
            query += " WHERE role = 'user' AND branchname = $1";
            params.push(req.user.branchname);
        }

        const { rows: employees } = await pool.query(query, params);

        res.json({
            success: true,
            employees: employees
        });
    } catch (error) {
        console.error('Error getting employees:', error);
        res.status(500).json({
            success: false,
            message: 'Error getting employees',
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});


