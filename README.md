# Vulnerable Web Application

⚠️ **WARNING: This application contains intentional security vulnerabilities for educational purposes only. DO NOT use in production!**

## Overview

This is a deliberately vulnerable Node.js web application designed to demonstrate common security vulnerabilities. It includes at least 10 different security issues that are commonly found in web applications.

## Installation

```bash
npm install
```

## Running the Application

```bash
npm start
```

The server will start on `http://localhost:3000`

## Security Vulnerabilities Included

### 1. **SQL Injection**
- **Location**: `/api/search` endpoint
- **Description**: User input is directly concatenated into SQL queries without sanitization
- **Exploit**: Try searching for `' OR '1'='1` to see how the query is constructed

### 2. **Insecure Direct Object Reference (IDOR)**
- **Location**: `/api/user/:id` endpoint
- **Description**: No authorization checks - users can access any user's data by changing the ID
- **Exploit**: Access `/api/user/1` or `/api/user/2` without authentication

### 3. **Sensitive Data Exposure**
- **Location**: `/api/user/:id` endpoint
- **Description**: Passwords are returned in API responses in plain text
- **Exploit**: Access any user endpoint to see their password

### 4. **Cross-Site Scripting (XSS)**
- **Location**: `/api/comment` endpoint and comments display
- **Description**: User input is stored and displayed without sanitization
- **Exploit**: Post a comment with `<script>alert('XSS')</script>`

### 5. **Command Injection**
- **Location**: `/api/ping` endpoint
- **Description**: User input is directly passed to shell commands
- **Exploit**: Try `8.8.8.8; ls` or `8.8.8.8 && dir` (Windows)

### 6. **Path Traversal**
- **Location**: `/api/file` endpoint
- **Description**: No validation of file paths allows accessing files outside intended directory
- **Exploit**: Try `../../../../etc/passwd` (Linux) or `..\\..\\..\\windows\\system32\\drivers\\etc\\hosts` (Windows)

### 7. **Code Injection (eval)**
- **Location**: `/api/calculate` endpoint
- **Description**: User input is executed as JavaScript code using `eval()`
- **Exploit**: Try `require('fs').readFileSync('package.json', 'utf8')`

### 8. **Weak Password Storage**
- **Location**: `/api/register` endpoint
- **Description**: Passwords are stored in plain text instead of being hashed
- **Exploit**: Register a user and check the in-memory database

### 9. **Missing Authentication/Authorization**
- **Location**: `/admin` endpoint
- **Description**: Admin panel is accessible without any authentication
- **Exploit**: Simply navigate to `/admin`

### 10. **Security Misconfiguration**
- **Location**: Server configuration
- **Description**: No security headers, debug information exposed, no rate limiting
- **Exploit**: Check response headers and error messages

## Educational Purpose

This application is designed for:
- Learning about web application security
- Security testing practice
- Understanding common vulnerabilities
- Security training and workshops

## How to Secure This Application

To fix these vulnerabilities, you would need to:

1. Use parameterized queries or ORM for database operations
2. Implement proper authentication and authorization
3. Hash passwords using bcrypt or similar
4. Sanitize and validate all user input
5. Use Content Security Policy (CSP) headers
6. Avoid using `eval()` and `exec()` with user input
7. Validate file paths and restrict access
8. Implement proper session management
9. Add rate limiting and security headers
10. Never expose sensitive data in API responses

## Disclaimer

This software is provided for educational purposes only. The authors are not responsible for any misuse of this code. Use responsibly and only in controlled environments.

# Test2
