import pickle
def bad_function(user_input):
    cursor.execute(f"SELECT * FROM data WHERE id = {user_input}")
    result = pickle.loads(user_input)