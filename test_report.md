⚠️ **CodeSage Security Report**

### 🔥 SQL Injection (Line 3)
**File**: `example.py`
**Code**:
```python
cursor.execute(f"SELECT * FROM data WHERE id = {user_input}")
```
**Fix**:
```python
# Вместо:
cursor.execute(f"SELECT * FROM users WHERE name = {name}")
# Используйте:
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
```
**Business Impact**: Risk of full database leak → GDPR fines up to €20M.

