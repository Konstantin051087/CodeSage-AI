# fixtures/vulnerable.py
import pickle

def get_user(name):
    # SQL-инъекция через f-строку
    cursor.execute(f"SELECT * FROM users WHERE name = {name}")

# Опасная функция
data = b"..."
result = pickle.loads(data)

# Цепочка вызовов (требует улучшения детектора)
db = get_db()
db.cursor().execute("SELECT * FROM admins WHERE id = " + admin_id)