const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3001; // Use process.env.PORT for dynamic port binding

app.use(cors());
app.use(bodyParser.json());

// PostgreSQL connection
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'mydatabase',
    password: 'root',
    port: 5432,
});

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
    const { title, name } = req.body;

    // Validate user_id and title
    if (!title) {
        return res.status(400).json({ error: 'Title is required' });
    }

    const user_id = req.user.id; // Retrieve user_id from authenticated user

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


app.get('/forms', authenticateToken, async (req, res) => {
    const user_id = req.user.id; // Retrieve user_id from authenticated user


    try {
        const result = await pool.query('SELECT * FROM forms WHERE user_id = $1', [user_id]);
        res.status(200).json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete a form
app.delete('/forms/:formId', authenticateToken, async (req, res) => {
    const { formId } = req.params;
    const user_id = req.user.id; // Retrieve user_id from authenticated user

    try {
        // Verify that the form exists and belongs to the authenticated user
        const formQuery = 'SELECT * FROM forms WHERE id = $1 AND user_id = $2';
        const formResult = await pool.query(formQuery, [formId, user_id]);

        if (formResult.rows.length === 0) {
            return res.status(404).json({ error: 'Form not found' });
        }

        // Delete the form
        const deleteQuery = 'DELETE FROM forms WHERE id = $1 AND user_id = $2';
        await pool.query(deleteQuery, [formId, user_id]);

        res.status(204).send(); // 204 No Content
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

    const validTypes = [
        'single_input', 'multi_input', 'phone_number',
        'single_select', 'multi_select', 'dropdown_list',
        'date', 'give_star_rating', 'signature', 'file_upload'
    ];

    if (!validTypes.includes(type)) {
        return res.status(400).json({ error: 'Invalid field type' });
    }

    try {
        let query, values;
        if (['single_input', 'multi_input', 'phone_number', 'signature', 'file_upload', 'date', 'give_star_rating'].includes(type)) {
            query = 'INSERT INTO fields (form_id, type, label) VALUES ($1, $2, $3) RETURNING *';
            values = [formId, type, label];
        } else {
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
