const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const path = require('path');
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

let db = null;

/**
 * Serve the dashboard
 */
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

/**
 * Connect to user database (READ ONLY)
 */
app.post('/connect', (req, res) => {
    const { path } = req.body;

    if (!path) {
        return res.status(400).send("Database path required");
    }

    // Close existing connection if any
    if (db) {
        db.close();
        db = null;
    }

    db = new sqlite3.Database(path, sqlite3.OPEN_READONLY, (err) => {
        if (err) {
            console.error(err.message);
            db = null;
            return res.status(500).send("Failed to connect");
        }
        res.send("Connected to user DB");
    });
});

/**
 * Get all tables
 */
app.get('/tables', (req, res) => {
    if (!db) return res.status(500).send("No DB connected");

    db.all(
        "SELECT name FROM sqlite_master WHERE type='table'",
        [],
        (err, rows) => {
            if (err) return res.status(500).send(err.message);
            res.json(rows);
        }
    );
});

/**
 * Get table data (READ ONLY)
 */
app.get('/table/:name', (req, res) => {
    if (!db) return res.status(500).send("No DB connected");

    const table = req.params.name;

    // prevent SQL injection
    if (!/^[a-zA-Z0-9_]+$/.test(table)) {
        return res.status(400).send("Invalid table name");
    }

    db.all(`SELECT * FROM ${table}`, [], (err, rows) => {
        if (err) return res.status(500).send(err.message);
        res.json(rows);
    });
});

/**
 * Aggregation endpoint
 * Example:
 * /aggregate/users?column=age&op=avg
 */
app.get('/aggregate/:table', (req, res) => {
    if (!db) return res.status(500).send("No DB connected");

    const table = req.params.table;
    const { column, op } = req.query;

    // validate inputs
    if (!/^[a-zA-Z0-9_]+$/.test(table)) {
        return res.status(400).send("Invalid table name");
    }

    if (!column || !/^[a-zA-Z0-9_]+$/.test(column)) {
        return res.status(400).send("Invalid column name");
    }

    const allowedOps = ['sum', 'avg', 'count', 'min', 'max'];
    if (!allowedOps.includes(op)) {
        return res.status(400).send("Invalid operation");
    }

    const query = `SELECT ${op.toUpperCase()}(${column}) as result FROM ${table}`;

    db.get(query, [], (err, row) => {
        if (err) return res.status(500).send(err.message);
        res.json(row);
    });
});

/**
 * Disconnect DB
 */
app.post('/disconnect', (req, res) => {
    if (db) {
        db.close();
        db = null;
    }
    res.send("Disconnected");
});

app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});