import os
from huggingface_hub import login

def main():
    print("Пожалуйста, введите ваш Hugging Face токен")
    print("Токен можно получить по адресу: https://huggingface.co/settings/tokens")
    
    # Чтение токена из переменной окружения или ввод пользователя
    token = os.environ.get("HUGGING_FACE_HUB_TOKEN")
    
    if not token:
        token = input("Введите токен: ").strip()
    
    if token:
        try:
            login(token=token)
            print("\n✅ Успешная аутентификация в Hugging Face!")
            print("Теперь вы можете использовать модели и датасеты из Hugging Face Hub")
            
            # Сохранение токена в переменную окружения для текущей сессии
            os.environ["HUGGING_FACE_HUB_TOKEN"] = token
            
            # Опционально: сохранение токена в файл .env для последующих запусков
            env_path = os.path.join(os.path.dirname(__file__), "../../.env")
            with open(env_path, "w") as f:
                f.write(f"HUGGING_FACE_HUB_TOKEN={token}\n")
            print(f"Токен сохранен в файл .env для последующих запусков")
            
        except Exception as e:
            print(f"\n❌ Ошибка аутентификации: {str(e)}")
            print("Пожалуйста, проверьте правильность токена и наличие интернет-соединения")
    else:
        print("\n❌ Токен не введен. Аутентификация невозможна")

if __name__ == "__main__":
    main()