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
# cursor.execute(f"SELECT * FROM users WHERE name = {name}")
# или
# cursor.execute("SELECT * FROM users WHERE id = " + user_id)
# Используйте параметризованный запрос:
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
```
**Business Impact**: Risk of full database leak → GDPR fines up to €20M.

### ⚡ Dangerous Function `pickle.loads` (Line 4)
**Fix**: Avoid using this dangerous function. Prefer safer alternatives.
**Business Impact**: Remote code execution → server takeover.

