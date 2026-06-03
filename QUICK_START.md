# Blind SQL Injector - Quick Integration (5 Minutes)

## Step-by-Step Integration

### Step 1: Copy Files
```bash
# Copy the HTML template
cp blindsql.html templates/

# Copy the Python module
cp blindsql.py ./

# Copy the routes file
cp blindsql_routes.py ./
```

### Step 2: Edit server.py (Add 2 lines)

**Find this section** (around line 26):
```python
from tools import tools_bp

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")
app.register_blueprint(tools_bp)
```

**Add these 2 lines after importing tools_bp:**
```python
from blindsql_routes import blindsql_bp

# ... then after registering tools_bp:
app.register_blueprint(blindsql_bp)
```

**Result should look like:**
```python
from tools import tools_bp
from blindsql_routes import blindsql_bp  # ← ADD THIS

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")
app.register_blueprint(tools_bp)
app.register_blueprint(blindsql_bp)  # ← ADD THIS
```

### Step 3: Verify Installation
Start your Flask app and navigate to:
```
http://localhost:5000/blindsql
```

You should see the Blind SQL Injector interface!

## Usage Walkthrough

### 1️⃣ Get Your Target Request
From Burp Suite → Proxy → HTTP History:
- Right-click request → Copy to file (or Copy as curl)
- Or manually copy the raw request

Example:
```
GET /filter?category=Gifts HTTP/2.0
Host: 0aa9000f04dc88db8436782300cb0060.web-security-academy.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:150.0)
Cookie: TrackingId=x; session=QtJaOLgfAkdX2wB8QTlF4c0vACFRhNwR
```

### 2️⃣ Paste into Tool
1. Go to `/blindsql`
2. Paste raw request in "HTTP Request (Raw Format)" box
3. Click anywhere else to parse it
4. Tool automatically detects parameters like `TrackingId`, `session`, `category`

### 3️⃣ Select Injection Point
- Radio button appears for each detected parameter
- Choose the vulnerable one (usually from cookie if you found it)
- Example: Select `TrackingId`

### 4️⃣ Configure Extraction
```
Database Type: Auto-detect (or MySQL if you know)
Injection Type: Boolean-based (faster!)
True Indicator: "Welcome" or "Product" (appears when query is TRUE)
Extraction Mode: Get Table Names
```

### 5️⃣ Click Start
Watch console as it:
- Tests injection: `' OR '1'='1`
- Confirms it works
- Extracts table names character-by-character
- Shows results in real-time

## Real Example: PortSwigger Lab

### The Vulnerability
Lab: Blind SQL injection with conditional responses
URL: `https://0aa9000f04dc88db8436782300cb0060.web-security-academy.net/filter?category=Gifts`

### Step-by-step:

**1. Copy the request:**
```
GET /filter?category=Gifts HTTP/2.0
Host: 0aa9000f04dc88db8436782300cb0060.web-security-academy.net
User-Agent: Mozilla/5.0
Cookie: TrackingId=<payload>; session=QtJaOLgfAkdX2wB8QTlF4c0vACFRhNwR
```

**2. Settings:**
- Injection Point: `TrackingId` (from cookie)
- Injection Type: `Boolean-based`
- True Indicator: `"Welcome"` (this appears in the page when TRUE)
- Database Type: `Auto-detect`
- Mode: `Get Table Names`

**3. Run:**
Click Start → Tool extracts all table names automatically

**4. Extract Data:**
- Change Mode to: `Extract Data`
- Table Name: `users`
- Column Name: `password`
- Click Start

Result: All passwords extracted! 🎯

## Common Issues & Fixes

| Issue | Solution |
|-------|----------|
| "Injection test failed" | Check `true_indicator` - what appears on the page when TRUE? |
| Parameters not detected | Make sure you pasted the full raw request including headers |
| Slow extraction | Use `Boolean-based` instead of time-based (10x faster) |
| "No tables found" | Database might be PostgreSQL/SQL Server - try changing type |
| Request format error | Copy from Burp as "Raw" format, not "cURL" format |

## How to Find the True Indicator

In Burp Suite:
1. Send normal request → See what's in response
2. Send with `' OR '1'='1` → See what changes
3. Send with `' OR '1'='2` → See the difference
4. The string that appears ONLY when query is TRUE = your indicator

Examples:
- Page shows "Welcome back!" → Use `"Welcome"`
- Page shows "3 products found" → Use `"products"`
- Page shows different layout → Look at HTML for unique text
- Use browser DevTools → Inspect HTML differences

## What Gets Extracted

### Table Names
```
users
admin
products
orders
customers
```

### Column Names (from selected table)
```
id
username
email
password
secret
```

### Actual Data
```
[0] admin123
[1] P@ssw0rd!
[2] secret_key_here
[3] encrypted_data
```

## Advanced: Manual Testing First

Before using the tool, verify the injection manually:

```bash
# Test with curl
curl "http://target/filter?id=1' OR '1'='1" 
# Compare response with:
curl "http://target/filter?id=1' OR '1'='2"
```

If TRUE query shows different content than FALSE query → You're injectable!

## Architecture

```
┌─────────────────────────────────────────┐
│         blindsql.html (Frontend)        │
│  - Request pasting                      │
│  - Parameter detection & selection      │
│  - Real-time console logging            │
│  - Results display                      │
└──────────────┬──────────────────────────┘
               │ (JSON POST /blindsql-start)
               ↓
┌──────────────────────────────────────────┐
│      blindsql_routes.py (Flask)          │
│  - Route handlers                        │
│  - Task management                       │
│  - Real-time task status                 │
└──────────────┬──────────────────────────┘
               │
               ↓
┌──────────────────────────────────────────┐
│       blindsql.py (Core Logic)           │
│  - Request parsing                       │
│  - Payload injection                     │
│  - Response analysis                     │
│  - Character extraction                  │
└──────────────────────────────────────────┘
```

## Requirements

```
requests library
Python 3.7+
Flask (already installed)
```

If requests is missing:
```bash
pip install requests
```

## Next Steps After Setup

1. ✅ Copy 3 files
2. ✅ Edit server.py (2 lines)
3. ✅ Start Flask app
4. ✅ Navigate to `/blindsql`
5. ✅ Start hacking!

## Security Notes

⚠️ **Only use on authorized targets!**

- This is for penetration testing only
- Get written authorization first
- Follow responsible disclosure
- Don't access unauthorized data
- Respect all laws and policies

## What Makes This Tool Special

✨ **Why use this over manual testing:**
- ⚡ 100x faster than manual extraction
- 🎯 Automatic parameter detection
- 📊 Real-time progress & results
- 🔧 Supports all major databases
- 🎨 Professional UI matching your existing tools
- 🔐 Integrated with your auth system

## Support

Problems? Check:
1. Browser console (F12) for JavaScript errors
2. Flask terminal for Python errors
3. BLINDSQL_README.md for detailed info
4. Ensure all 3 files are in correct locations

---

**You're ready to go!** 🚀

Visit `http://localhost:5000/blindsql` after setup.
