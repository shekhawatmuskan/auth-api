const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
const port = 3001;

app.use(cors());

// PostgreSQL connection
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'mydatabase',
    password: 'root',
    port: 5432,
});
module.exports = pool;

app.use(bodyParser.json());

// Middleware for authenticating JWT tokens
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token is missing or invalid' });
    }

    jwt.verify(token, 'your_jwt_secret', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Signup API
app.post('/signup', async (req, res) => {
    const { email, password, username } = req.body;

    if (!email || !password || !username) {
        return res.status(400).json({ error: 'Email, password, and username are required' });
    }

    try {
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) {
            return res.status(400).json({ error: 'User already has an account' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *', [email, hashedPassword, username]);
        res.status(201).json({ message: 'User created successfully', user: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login API
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(400).json({ error: 'Please sign up first' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, 'your_jwt_secret', { expiresIn: '1h' });
        res.status(200).json({ message: 'Login successful', token, user_id: user.id });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create a form
app.post('/forms', authenticateToken, async (req, res) => {
    const {  title, name } = req.body;

    // Validate user_id and title
    if ( !title) {
        return res.status(400).json({ error: 'title are required' });
    }

    try {
        const query = 'INSERT INTO forms (user_id, title, name) VALUES ($1, $2, $3) RETURNING *';
        const values = [user_id, title, name];
        const result = await pool.query(query, values);
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add fields to a form
app.post('/forms/:formId/fields', authenticateToken, async (req, res) => {
    const { formId } = req.params;
    const { type, label, options } = req.body;

    if (!type || !label) {
        return res.status(400).json({ error: 'Type and label are required' });
    }

    try {
        // Validate type
        const validTypes = [
            'single_input', 'multi_input', 'phone_number',
            'single_select', 'multi_select', 'dropdown_list',
            'date', 'give_star_rating', 'signature', 'file_upload'
        ];

        if (!validTypes.includes(type)) {
            return res.status(400).json({ error: 'Invalid field type' });
        }

        // Insert field into database
        let query, values;
        if (type === 'single_input' || type === 'multi_input' || type === 'phone_number' ||
            type === 'signature' || type === 'file_upload' || type === 'date' || type === 'give_star_rating') {
            query = 'INSERT INTO fields (form_id, type, label) VALUES ($1, $2, $3) RETURNING *';
            values = [formId, type, label];
        } else if (type === 'single_select' || type === 'multi_select' || type === 'dropdown_list') {
            if (!options || options.length === 0) {
                return res.status(400).json({ error: 'Options are required for this field type' });
            }
            query = 'INSERT INTO fields (form_id, type, label, options) VALUES ($1, $2, $3, $4) RETURNING *';
            values = [formId, type, label, options];
        }

        const result = await pool.query(query, values);
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get forms by user
app.get('/users/:userId/forms', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    try {
        const query = 'SELECT * FROM forms WHERE user_id = $1';
        const values = [userId];
        const result = await pool.query(query, values);
        res.status(200).json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get fields for a form
app.get('/forms/:formId/fields', authenticateToken, async (req, res) => {
    const { formId } = req.params;
    try {
        const query = 'SELECT * FROM fields WHERE form_id = $1';
        const values = [formId];
        const result = await pool.query(query, values);
        res.status(200).json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
