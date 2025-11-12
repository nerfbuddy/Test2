const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;

// Rate limiting configuration
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10 // limit each IP to 10 requests per windowMs
});

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
// FIXED: Added rate limiting
app.get('/', generalLimiter, (req, res) => {
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
// FIXED: Added input validation and sanitization, rate limiting
app.post('/api/ping', strictLimiter, (req, res) => {
  const host = req.body.host;
  
  // Validate host input - only allow alphanumeric, dots, hyphens, and colons (for IPv6)
  // This prevents command injection by restricting input to valid hostname/IP format
  if (!host || typeof host !== 'string') {
    return res.status(400).json({ error: 'Invalid host parameter' });
  }
  
  // Whitelist validation: only allow valid hostname/IP characters
  const hostnamePattern = /^[a-zA-Z0-9.\-:]+$/;
  if (!hostnamePattern.test(host)) {
    return res.status(400).json({ error: 'Invalid host format. Only alphanumeric characters, dots, hyphens, and colons are allowed.' });
  }
  
  // Additional length check to prevent extremely long inputs
  if (host.length > 253) { // Maximum hostname length per RFC
    return res.status(400).json({ error: 'Hostname too long' });
  }
  
  // Use execFile or spawn with array arguments for better security, but for ping we'll validate input
  // For Windows, use ping -n 4, for Unix use ping -c 4
  const isWindows = process.platform === 'win32';
  const pingCommand = isWindows ? `ping -n 4 ${host}` : `ping -c 4 ${host}`;
  
  exec(pingCommand, { timeout: 5000 }, (error, stdout, stderr) => {
    if (error) {
      res.json({ error: error.message, output: stderr });
    } else {
      res.json({ success: true, output: stdout });
    }
  });
});

// VULNERABILITY #8: Path Traversal - No path validation
// FIXED: Added path validation and sanitization, rate limiting
app.get('/api/file', strictLimiter, (req, res) => {
  const filename = req.query.filename;
  
  // Validate filename input
  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'Invalid filename parameter' });
  }
  
  // Prevent path traversal attacks by checking for .. and path separators
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Invalid filename. Path traversal is not allowed.' });
  }
  
  // Only allow alphanumeric, dots, hyphens, and underscores in filename
  const filenamePattern = /^[a-zA-Z0-9.\-_]+$/;
  if (!filenamePattern.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename format' });
  }
  
  // Construct safe path
  const filesDir = path.join(__dirname, 'files');
  const filePath = path.join(filesDir, filename);
  
  // Resolve to absolute path and ensure it's within the files directory
  const resolvedPath = path.resolve(filePath);
  const resolvedDir = path.resolve(filesDir);
  
  // Check that the resolved path is within the allowed directory
  if (!resolvedPath.startsWith(resolvedDir)) {
    return res.status(400).json({ error: 'Access denied. Path traversal detected.' });
  }
  
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      res.status(404).json({ error: 'File not found' });
    } else {
      res.json({ content: data });
    }
  });
});

// VULNERABILITY #9: Code Injection - Using eval() with user input
// FIXED: Replaced eval() with safe math expression evaluator
app.post('/api/calculate', (req, res) => {
  const expression = req.body.expression;
  
  if (!expression || typeof expression !== 'string') {
    return res.status(400).json({ error: 'Invalid expression parameter' });
  }
  
  // Safe math expression evaluator - only allows basic arithmetic operations
  // This prevents code injection by using a simple parser instead of eval/Function
  const safeEvaluate = (expr) => {
    // Remove all whitespace
    expr = expr.replaceAll(/\s/g, '');
    
    // Only allow digits, decimal points, parentheses, and basic operators
    const safePattern = /^[0-9+\-*/().]+$/;
    if (!safePattern.test(expr)) {
      throw new Error('Invalid characters in expression. Only numbers and basic operators (+, -, *, /) are allowed.');
    }
    
    // Check for balanced parentheses
    let parenCount = 0;
    for (let char of expr) {
      if (char === '(') parenCount++;
      if (char === ')') parenCount--;
      if (parenCount < 0) throw new Error('Unbalanced parentheses');
    }
    if (parenCount !== 0) throw new Error('Unbalanced parentheses');
    
    // Simple recursive descent parser for basic arithmetic (no eval/Function)
    let pos = 0;
    
    const parseNumber = () => {
      let numStr = '';
      while (pos < expr.length && /[0-9.]/.test(expr[pos])) {
        numStr += expr[pos];
        pos++;
      }
      const num = Number.parseFloat(numStr);
      if (Number.isNaN(num)) throw new Error('Invalid number');
      return num;
    };
    
    const parseExpression = () => {
      let result = parseTerm();
      while (pos < expr.length && (expr[pos] === '+' || expr[pos] === '-')) {
        const op = expr[pos++];
        const term = parseTerm();
        result = op === '+' ? result + term : result - term;
      }
      return result;
    };
    
    const parseTerm = () => {
      let result = parseFactor();
      while (pos < expr.length && (expr[pos] === '*' || expr[pos] === '/')) {
        const op = expr[pos++];
        const factor = parseFactor();
        if (op === '*') {
          result *= factor;
        } else {
          if (factor === 0) throw new Error('Division by zero');
          result /= factor;
        }
      }
      return result;
    };
    
    const parseFactor = () => {
      if (pos >= expr.length) throw new Error('Unexpected end of expression');
      
      if (expr[pos] === '(') {
        pos++; // skip '('
        const result = parseExpression();
        if (pos >= expr.length || expr[pos] !== ')') {
          throw new Error('Missing closing parenthesis');
        }
        pos++; // skip ')'
        return result;
      }
      
      if (expr[pos] === '-') {
        pos++;
        return -parseFactor();
      }
      
      if (expr[pos] === '+') {
        pos++;
        return parseFactor();
      }
      
      return parseNumber();
    };
    
    try {
      const result = parseExpression();
      if (pos < expr.length) {
        throw new Error('Unexpected characters at end of expression');
      }
      return result;
    } catch (e) {
      if (e instanceof Error) {
        throw e;
      }
      throw new Error('Invalid expression syntax');
    }
  };
  
  try {
    const result = safeEvaluate(expression);
    // Check if result is a valid number
    if (typeof result !== 'number' || !Number.isFinite(result)) {
      throw new TypeError('Result is not a valid number');
    }
    res.json({ result: result });
  } catch (error) {
    res.status(400).json({ error: error.message });
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
// FIXED: Added HTML escaping to prevent XSS
app.get('/admin', (req, res) => {
  // HTML escape function to prevent XSS
  const escapeHtml = (text) => {
    if (text === null || text === undefined) return '';
    return String(text)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  };
  
  // Escape JSON output to prevent XSS
  const escapedUsers = escapeHtml(JSON.stringify(users, null, 2));
  const escapedPosts = escapeHtml(JSON.stringify(posts, null, 2));
  
  res.send(`
    <html>
      <head><title>Admin Panel</title></head>
      <body>
        <h1>Admin Panel</h1>
        <p>All Users:</p>
        <pre>${escapedUsers}</pre>
        <p>All Posts:</p>
        <pre>${escapedPosts}</pre>
      </body>
    </html>
  `);
});

app.listen(PORT, () => {
  console.log(`Vulnerable server running on http://localhost:${PORT}`);
  console.log('WARNING: This application contains intentional security vulnerabilities!');
});

