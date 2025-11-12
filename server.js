const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const app = express();
const PORT = 3000;

// VULNERABILITY #1: Security Misconfiguration - No security headers, debug mode enabled
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// In-memory "database" for demonstration
let users = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin', email: 'admin@example.com' },
  { id: 2, username: 'user1', password: 'password', role: 'user', email: 'user1@example.com' }
];

let posts = [
  { id: 1, title: 'Welcome', content: 'This is a test post', author: 'admin' },
  { id: 2, title: 'Hello World', content: 'Another test post', author: 'user1' }
];

// VULNERABILITY #2: Missing Authentication - No session management, authentication bypass
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// VULNERABILITY #3: SQL Injection - Direct string concatenation in queries
app.post('/api/search', (req, res) => {
  const searchTerm = req.body.term;
  // Simulated SQL injection vulnerability
  const query = `SELECT * FROM users WHERE username = '${searchTerm}'`;
  console.log('Executing query:', query);
  
  // Simulate finding users
  const results = users.filter(u => u.username.includes(searchTerm));
  res.json({ query: query, results: results });
});

// VULNERABILITY #4: Insecure Direct Object Reference (IDOR) - No authorization checks
app.get('/api/user/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const user = users.find(u => u.id === userId);
  
  if (user) {
    // VULNERABILITY #5: Sensitive Data Exposure - Returning passwords in response
    res.json({
      id: user.id,
      username: user.username,
      password: user.password, // Should never expose passwords!
      email: user.email,
      role: user.role
    });
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// VULNERABILITY #6: Cross-Site Scripting (XSS) - No input sanitization
app.post('/api/comment', (req, res) => {
  const comment = req.body.comment;
  const username = req.body.username || 'anonymous';
  
  // Storing user input without sanitization
  const newComment = {
    id: posts.length + 1,
    author: username,
    content: comment, // XSS vulnerability - no sanitization
    timestamp: new Date()
  };
  
  posts.push(newComment);
  res.json({ success: true, comment: newComment });
});

app.get('/api/comments', (req, res) => {
  // Returning unsanitized comments - XSS in response
  res.json(posts);
});

// VULNERABILITY #7: Command Injection - Executing user input as shell commands
app.post('/api/ping', (req, res) => {
  const host = req.body.host;
  
  // Command injection vulnerability
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    if (error) {
      res.json({ error: error.message, output: stderr });
    } else {
      res.json({ success: true, output: stdout });
    }
  });
});

// VULNERABILITY #8: Path Traversal - No path validation
app.get('/api/file', (req, res) => {
  const filename = req.query.filename;
  
  // Path traversal vulnerability
  const filePath = path.join(__dirname, 'files', filename);
  
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      res.status(500).json({ error: 'File not found' });
    } else {
      res.json({ content: data });
    }
  });
});

// VULNERABILITY #9: Code Injection - Using eval() with user input
app.post('/api/calculate', (req, res) => {
  const expression = req.body.expression;
  
  // Code injection vulnerability - using eval()
  try {
    const result = eval(expression);
    res.json({ result: result });
  } catch (error) {
    res.json({ error: error.message });
  }
});

// VULNERABILITY #10: Weak Password Storage - Plain text passwords
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;
  
  // Storing passwords in plain text - should be hashed!
  const newUser = {
    id: users.length + 1,
    username: username,
    password: password, // Plain text - major vulnerability!
    email: email,
    role: 'user'
  };
  
  users.push(newUser);
  res.json({ success: true, user: newUser });
});

// Login endpoint with weak authentication
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username && u.password === password);
  
  if (user) {
    // No proper session tokens, just returning user data
    res.json({ 
      success: true, 
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  } else {
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

// Admin panel - no authentication check
app.get('/admin', (req, res) => {
  res.send(`
    <html>
      <head><title>Admin Panel</title></head>
      <body>
        <h1>Admin Panel</h1>
        <p>All Users:</p>
        <pre>${JSON.stringify(users, null, 2)}</pre>
        <p>All Posts:</p>
        <pre>${JSON.stringify(posts, null, 2)}</pre>
      </body>
    </html>
  `);
});

app.listen(PORT, () => {
  console.log(`Vulnerable server running on http://localhost:${PORT}`);
  console.log('WARNING: This application contains intentional security vulnerabilities!');
});

