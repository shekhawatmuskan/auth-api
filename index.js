const express = require("express");
const bodyParser = require("body-parser");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const port = process.env.PORT || 3001;

app.use(cors());
app.use(bodyParser.json());

// PostgreSQL connection
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "mydatabase",
  password: "root",
  port: 5432,
});

// Middleware for authenticating JWT tokens
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ error: "Access token is missing or invalid" });
  }

  jwt.verify(token, "your_jwt_secret", (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

// Signup API
app.post("/signup", async (req, res) => {
  const { email, password, username } = req.body;

  if (!email || !password || !username) {
    return res
      .status(400)
      .json({ error: "Email, password, and username are required" });
  }

  try {
    const userExists = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email],
    );
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: "User already has an account" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *",
      [email, hashedPassword, username],
    );
    res
      .status(201)
      .json({ message: "User created successfully", user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Login API
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: "Please sign up first" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      "your_jwt_secret",
      { expiresIn: "1h" },
    );
    res
      .status(200)
      .json({ message: "Login successful", token, user_id: user.id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create a form
app.post("/forms", authenticateToken, async (req, res) => {
  const { title, name } = req.body;

  // Validate user_id and title
  if (!title) {
    return res.status(400).json({ error: "Title is required" });
  }

  const user_id = req.user.id;

  try {
    const query =
      "INSERT INTO forms (user_id, title, name) VALUES ($1, $2, $3) RETURNING *";
    const values = [user_id, title, name];
    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/forms", authenticateToken, async (req, res) => {
  const user_id = req.user.id; // Retrieve user_id from authenticated user

  try {
    const result = await pool.query("SELECT * FROM forms WHERE user_id = $1", [
      user_id,
    ]);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete a form
app.delete("/forms/:formId", authenticateToken, async (req, res) => {
  const { formId } = req.params;
  const user_id = req.user.id; // Retrieve user_id from authenticated user

  try {
    // Verify that the form exists and belongs to the authenticated user
    const formQuery = "SELECT * FROM forms WHERE id = $1 AND user_id = $2";
    const formResult = await pool.query(formQuery, [formId, user_id]);

    if (formResult.rows.length === 0) {
      return res.status(404).json({ error: "Form not found" });
    }

    // Delete the form
    const deleteQuery = "DELETE FROM forms WHERE id = $1 AND user_id = $2";
    await pool.query(deleteQuery, [formId, user_id]);

    res.status(204).send(); // 204 No Content
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});
// Add a block to a form
app.post("/forms/:formId/blocks", authenticateToken, async (req, res) => {
  const { formId } = req.params;
  const { blockType, blockData } = req.body;
  const userId = req.user.id;

  // Validate blockType and blockData
  if (!blockType || !blockData) {
    return res.status(400).json({ error: "Block type and data are required" });
  }

  try {
    const formQuery = "SELECT * FROM forms WHERE id = $1 AND user_id = $2";
    const formResult = await pool.query(formQuery, [formId, userId]);

    if (formResult.rows.length === 0) {
      return res.status(404).json({ error: "Form not found" });
    }

    const form = formResult.rows[0];
    const blocks = form.blocks || [];
    blocks.push({ blockType, blockData });

    const updateQuery =
      "UPDATE forms SET blocks = $1 WHERE id = $2 RETURNING *";
    const result = await pool.query(updateQuery, [blocks, formId]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});
// Get blocks of a form
app.get("/forms/:formId/blocks", authenticateToken, async (req, res) => {
  const { formId } = req.params;
  const userId = req.user.id; // Retrieve user_id from authenticated user

  try {
    // Verify that the form exists and belongs to the authenticated user
    const formQuery = "SELECT * FROM forms WHERE id = $1 AND user_id = $2";
    const formResult = await pool.query(formQuery, [formId, userId]);

    if (formResult.rows.length === 0) {
      return res.status(404).json({ error: "Form not found" });
    }

    const form = formResult.rows[0];
    const blocks = form.blocks || [];

    res.status(200).json(blocks);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
