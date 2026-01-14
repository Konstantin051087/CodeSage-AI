import json
import os
import random
import re
import time
from collections import Counter
from github import Github
from github.Auth import Token
from tqdm import tqdm
import logging
import argparse
from typing import Dict, List, Optional

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def collect_sql_injections(max_repos=50, output_dir="ai_training/datasets"):
    """
    Собирает примеры SQL-инъекций из GitHub
    
    Args:
        max_repos: Максимальное количество репозиториев для анализа
        output_dir: Директория для сохранения результатов
    
    Returns:
        List[Dict]: Список собранных примеров SQL-инъекций
    """
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        logger.error("GITHUB_TOKEN не установлен. Пожалуйста, установите переменную окружения.")
        logger.error("Токен можно получить по адресу: https://github.com/settings/tokens (требуются права public_repo)")
        return []
    
    try:
        auth = Token(github_token)
        g = Github(auth=auth)
        
        # Проверка подключения
        user = g.get_user()
        rate_limit = g.get_rate_limit()
        logger.info(f"Подключено к GitHub API как пользователь: {user.login}")
        logger.info(f"Текущие лимиты: core: {rate_limit.resources.core.remaining}/{rate_limit.resources.core.limit}, "
                   f"search: {rate_limit.resources.search.remaining}/{rate_limit.resources.search.limit}")
    except Exception as e:
        logger.error(f"Ошибка подключения к GitHub API: {str(e)}")
        raise
    
    logger.info("Начало сбора примеров уязвимостей...")
    
    # Более точные запросы для поиска SQL-инъекций
    sql_queries = [
        "sql injection fix in:file language:python",
        "sql injection vulnerability fix in:file language:python",
        "sql injection patch in:file language:python",
        "\"execute(f\\\"\" in:file language:python",
        "\"execute(\" +\" in:file language:python"
    ]
    
    sql_examples = []
    repo_count = 0
    
    for query in sql_queries:
        if repo_count >= max_repos:
            break
            
        logger.info(f"Поиск SQL-инъекций по запросу: '{query}'")
        
        try:
            repos = g.search_repositories(query, sort="stars", order="desc")
            
            for repo in tqdm(repos, desc=f"Сбор репозиториев по запросу '{query}'"):
                if repo_count >= max_repos:
                    break
                
                try:
                    logger.debug(f"Анализ репозитория: {repo.full_name}")
                    
                    # Поиск файлов с кодом
                    contents = repo.get_contents("")
                    files_to_check = []
                    processed_paths = set()
                    
                    # Сначала собираем все Python файлы
                    while contents:
                        file_content = contents.pop(0)
                        if file_content.path in processed_paths:
                            continue
                            
                        processed_paths.add(file_content.path)
                        
                        if file_content.type == "dir" and len(contents) < 100:  # Ограничиваем глубину поиска
                            try:
                                contents.extend(repo.get_contents(file_content.path))
                            except Exception as e:
                                continue
                        elif file_content.type == "file" and file_content.path.endswith(".py"):
                            files_to_check.append(file_content)
                    
                    # Анализ Python файлов на предмет SQL-уязвимостей
                    for file in files_to_check[:10]:  # Ограничиваем количество проверяемых файлов
                        try:
                            file_content = repo.get_contents(file.path).decoded_content.decode('utf-8', errors='ignore')
                            lines = file_content.split('\n')
                            
                            # Проверка каждой строки на наличие паттернов SQL-инъекций
                            sql_patterns = [
                                r'execute\s*\(\s*f["\'].*\{.*\}.*["\']\s*\)',
                                r'execute\s*\(\s*.*\+.*\)',
                                r'execute\s*\(\s*.*\%.*\)'
                            ]
                            
                            for line_num, line in enumerate(lines, 1):
                                for pattern in sql_patterns:
                                    if re.search(pattern, line, re.IGNORECASE):
                                        # Создаем контекст вокруг уязвимости
                                        context_lines = max(0, line_num - 3), min(len(lines), line_num + 3)
                                        code_context = "\n".join([
                                            f"{i+1}: {lines[i]}" if i+1 != line_num else f"{i+1}: >>> {lines[i].strip()} <<<"
                                            for i in range(context_lines[0], context_lines[1])
                                        ])
                                        
                                        example = {
                                            "repo": repo.full_name,
                                            "file_path": file.path,
                                            "line_number": line_num,
                                            "vulnerability_type": "sql_injection",
                                            "code_snippet": code_context,
                                            "code_before": line.strip(),
                                            "code_after": _get_sql_fix(line.strip()),
                                            "business_impact": "Risk of full database leak → GDPR fines up to €20M",
                                            "fix_recommendation": "Use parameterized queries with placeholders",
                                            "industry_context": "general"
                                        }
                                        sql_examples.append(example)
                                        logger.debug(f"Найдена SQL-инъекция в {repo.full_name}/{file.path}:{line_num}")
                                        break
                        except Exception as e:
                            continue
                
                except Exception as e:
                    logger.error(f"Ошибка при обработке репозитория {repo.full_name}: {str(e)}")
                    continue
                
                repo_count += 1
                if repo_count >= max_repos:
                    break
                time.sleep(1)  # Уважаем лимиты GitHub API
                
        except Exception as e:
            logger.error(f"Ошибка при поиске репозиториев по запросу '{query}': {str(e)}")
            continue
    
    # Если не удалось собрать достаточно примеров, используем шаблоны
    if len(sql_examples) < 10:
        logger.warning(f"Собрано недостаточно SQL-примеров ({len(sql_examples)}). Генерация дополнительных примеров.")
        sql_examples.extend(_generate_synthetic_sql_examples(50 - len(sql_examples)))
    
    # Сохранение результатов
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "sql_injections.json")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(sql_examples, f, indent=2, ensure_ascii=False)
    
    logger.info(f"✅ Успешно собрано {len(sql_examples)} примеров SQL-инъекций")
    return sql_examples

def generate_dangerous_functions(count=50, output_dir="ai_training/datasets"):
    """
    Генерирует сбалансированный набор примеров опасных функций
    
    Args:
        count: Количество генерируемых примеров
        output_dir: Директория для сохранения результатов
    
    Returns:
        List[Dict]: Список сгенерированных примеров опасных функций
    """
    examples = []
    
    # Шаблоны для различных опасных функций
    templates = {
        "pickle.loads": [
            {
                "code_before": "data = pickle.loads(user_input)",
                "code_after": "data = json.loads(user_input)",
                "context": "10: import pickle\n11: # Получение данных от пользователя\n12: >>> data = pickle.loads(user_input)\n13: process_data(data)",
                "business_impact": "Remote code execution → server takeover",
                "fix_recommendation": "Replace with safe alternatives (e.g., json.loads instead of pickle.loads)"
            },
            {
                "code_before": "result = pickle.loads(request.body)",
                "code_after": "result = json.loads(request.body)",
                "context": "5: import pickle\n6: from django.http import HttpRequest\n7: def process_request(request):\n8: >>> result = pickle.loads(request.body)\n9: return HttpResponse(result)",
                "business_impact": "Remote code execution → server takeover",
                "fix_recommendation": "Use json.loads() for safe deserialization of JSON data"
            }
        ],
        "eval": [
            {
                "code_before": "result = eval(user_input)",
                "code_after": "result = ast.literal_eval(user_input)",
                "context": "15: import ast\n16: # Вычисление выражения от пользователя\n17: >>> result = eval(user_input)\n18: print(f\"Result: {result}\")",
                "business_impact": "Arbitrary code execution → complete system compromise",
                "fix_recommendation": "Use ast.literal_eval() for safe evaluation of literals"
            },
            {
                "code_before": "value = eval(f\"{formula}\")",
                "code_after": "value = safe_formula_eval(formula)",
                "context": "22: formula = request.GET.get('formula', 'x+1')\n23: x = 10\n24: >>> value = eval(f\"{formula}\")\n25: return JsonResponse({'result': value})",
                "business_impact": "Arbitrary code execution → complete system compromise",
                "fix_recommendation": "Create a safe formula evaluator that only allows mathematical operations"
            }
        ],
        "exec": [
            {
                "code_before": "exec(user_code)",
                "code_after": "# Use a sandboxed execution environment or avoid dynamic execution",
                "context": "30: user_code = request.POST.get('code', '')\n31: # Динамическое выполнение кода\n32: >>> exec(user_code)\n33: return render(request, 'result.html', {'status': 'executed'})",
                "business_impact": "Malicious payload execution → data theft and service disruption",
                "fix_recommendation": "Avoid exec() — refactor to avoid dynamic code execution"
            }
        ],
        "jsonpickle.decode": [
            {
                "code_before": "obj = jsonpickle.decode(json_data)",
                "code_after": "obj = json.loads(json_data)",
                "context": "5: import jsonpickle\n6: # Десериализация данных\n7: >>> obj = jsonpickle.decode(json_data)\n8: return obj.process()",
                "business_impact": "Object injection → arbitrary code execution",
                "fix_recommendation": "Avoid jsonpickle.decode() — use standard json module"
            }
        ]
    }
    
    # Генерация примеров
    i = 0
    while len(examples) < count:
        for func_type, patterns in templates.items():
            for pattern in patterns:
                if len(examples) >= count:
                    break
                
                example = {
                    "repo": f"synthetic/{func_type}-example-{i}",
                    "file_path": f"utils{i % 3 + 1}.py",
                    "line_number": 15 + (i % 10),
                    "vulnerability_type": "dangerous_function",
                    "function": func_type,
                    "code_snippet": pattern["context"],
                    "code_before": pattern["code_before"],
                    "code_after": pattern["code_after"],
                    "business_impact": pattern["business_impact"],
                    "fix_recommendation": pattern["fix_recommendation"],
                    "industry_context": ["fintech", "healthcare", "ecommerce", "saas", "iot"][i % 5]
                }
                examples.append(example)
                i += 1
    
    # Сохранение результатов
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "dangerous_functions.json")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(examples, f, indent=2, ensure_ascii=False)
    
    logger.info(f"✅ Успешно сгенерировано {len(examples)} примеров опасных функций")
    return examples

def balance_dataset(sql_file="ai_training/datasets/sql_injections.json", 
                   dangerous_file="ai_training/datasets/dangerous_functions.json",
                   output_file="ai_training/datasets/balanced_vulnerabilities.json",
                   test_split=0.2):
    """
    Объединяет и балансирует датасет из разных источников
    
    Args:
        sql_file: Путь к файлу с SQL-инъекциями
        dangerous_file: Путь к файлу с опасными функциями
        output_file: Путь для сохранения сбалансированного датасета
        test_split: Доля тестовых данных
    
    Returns:
        Dict: Сбалансированный датасет
    """
    try:
        # Загрузка данных
        with open(sql_file, 'r', encoding='utf-8') as f:
            sql_examples = json.load(f)
        
        with open(dangerous_file, 'r', encoding='utf-8') as f:
            dangerous_examples = json.load(f)
        
        logger.info(f"Загружено {len(sql_examples)} SQL-инъекций и {len(dangerous_examples)} опасных функций")
        
        # Балансировка классов
        min_count = min(len(sql_examples), len(dangerous_examples))
        logger.info(f"Минимальное количество примеров для баланса: {min_count}")
        
        # Случайная выборка для баланса
        balanced_sql = random.sample(sql_examples, min_count)
        balanced_dangerous = random.sample(dangerous_examples, min_count)
        
        # Объединение данных
        combined_examples = balanced_sql + balanced_dangerous
        
        # Перемешивание данных
        random.shuffle(combined_examples)
        
        # Разделение на train/test
        split_idx = int(len(combined_examples) * (1 - test_split))
        train_examples = combined_examples[:split_idx]
        test_examples = combined_examples[split_idx:]
        
        # Подготовка итогового датасета
        dataset = {
            "metadata": {
                "total_examples": len(combined_examples),
                "train_examples": len(train_examples),
                "test_examples": len(test_examples),
                "class_distribution": dict(Counter([ex["vulnerability_type"] for ex in combined_examples]))
            },
            "train": train_examples,
            "test": test_examples
        }
        
        # Сохранение результатов
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, indent=2, ensure_ascii=False)
        
        logger.info(f"✅ Датасет успешно сбалансирован и сохранен в {output_file}")
        logger.info(f"Распределение классов: {dataset['metadata']['class_distribution']}")
        logger.info(f"Train/Test split: {len(train_examples)}/{len(test_examples)}")
        
        return dataset
    
    except Exception as e:
        logger.error(f"Ошибка при балансировке датасета: {str(e)}")
        return {}

def _get_sql_fix(vulnerable_line):
    """Генерирует пример исправления для SQL-инъекции"""
    if "f\"" in vulnerable_line or "f'" in vulnerable_line:
        return "cursor.execute(\"SELECT * FROM users WHERE name = %s\", (name,))"
    elif "+" in vulnerable_line:
        return "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
    elif "%" in vulnerable_line:
        return "cursor.execute(\"SELECT * FROM users WHERE email = %s\", (email,))"
    else:
        return "cursor.execute(\"SELECT * FROM table WHERE condition = %s\", (value,))"

def _generate_synthetic_sql_examples(count):
    """Генерирует синтетические примеры SQL-инъекций"""
    examples = []
    sql_templates = [
        {
            "code_before": "cursor.execute(f\"SELECT * FROM users WHERE name = {name}\")",
            "code_after": "cursor.execute(\"SELECT * FROM users WHERE name = %s\", (name,))",
            "context": "22: def get_user(name):\n23:     # Уязвимый код\n24: >>> cursor.execute(f\"SELECT * FROM users WHERE name = {name}\")\n25:"
        },
        {
            "code_before": "cursor.execute(\"SELECT * FROM users WHERE id = '\" + user_id + \"'\")", 
            "code_after": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
            "context": "10: user_id = request.GET['id']\n11: # Уязвимый запрос\n12: >>> cursor.execute(\"SELECT * FROM users WHERE id = '\" + user_id + \"'\")\n13:"
        },
        {
            "code_before": "query = \"SELECT * FROM products WHERE category = '%s'\" % category",
            "code_after": "query = \"SELECT * FROM products WHERE category = %s\"",
            "context": "5: category = input(\"Enter category: \")\n6: # Небезопасное форматирование\n7: >>> query = \"SELECT * FROM products WHERE category = '%s'\" % category\n8: cursor.execute(query)"
        },
        {
            "code_before": "cursor.execute(\"SELECT * FROM accounts WHERE balance > \" + str(min_balance))",
            "code_after": "cursor.execute(\"SELECT * FROM accounts WHERE balance > %s\", (min_balance,))",
            "context": "15: min_balance = request.form['min_balance']\n16: # Динамический запрос без параметризации\n17: >>> cursor.execute(\"SELECT * FROM accounts WHERE balance > \" + str(min_balance))\n18:"
        }
    ]
    
    for i in range(count):
        template = sql_templates[i % len(sql_templates)]
        example = {
            "repo": f"synthetic/example-{i}",
            "file_path": f"app{i % 4 + 1}.py",
            "line_number": 24 + (i % 5),
            "vulnerability_type": "sql_injection",
            "code_snippet": template["context"],
            "code_before": template["code_before"],
            "code_after": template["code_after"],
            "business_impact": "Risk of full database leak → GDPR fines up to €20M",
            "fix_recommendation": "Use parameterized queries with placeholders",
            "industry_context": ["fintech", "ecommerce", "healthcare", "saas"][i % 4]
        }
        examples.append(example)
    
    return examples

def check_class_balance(dataset_file):
    """Проверяет баланс классов в датасете"""
    try:
        with open(dataset_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Если это файл с балансированным датасетом
        if "train" in data:
            examples = data["train"] + data["test"]
        else:
            examples = data
        
        type_counts = {}
        for item in examples:
            vuln_type = item.get("vulnerability_type", "unknown")
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        logger.info("Распределение типов уязвимостей:")
        total = sum(type_counts.values())
        for vuln_type, count in type_counts.items():
            percentage = (count / total) * 100
            logger.info(f"- {vuln_type}: {count} ({percentage:.1f}%)")
        
        # Проверяем баланс
        if total > 0 and max(type_counts.values()) / min(type_counts.values()) > 3:
            logger.warning("Датасет несбалансирован. Рассмотрите возможность аугментации или сбора дополнительных данных.")
        else:
            logger.info("✅ Датасет сбалансирован по классам")
        
        return type_counts
    
    except Exception as e:
        logger.error(f"Ошибка при проверке баланса: {str(e)}")
        return {}

def main():
    parser = argparse.ArgumentParser(description='Сбор, генерация и балансировка датасета для обучения AI-модели')
    parser.add_argument("--max-repos", type=int, default=50, help="Максимальное количество репозиториев для анализа")
    parser.add_argument("--dangerous-count", type=int, default=100, help="Количество генерируемых примеров опасных функций")
    parser.add_argument("--test-split", type=float, default=0.2, help="Доля тестовых данных (0.0-1.0)")
    parser.add_argument("--output-dir", default="ai_training/datasets", help="Директория для сохранения результатов")
    parser.add_argument("--final-output", default="ai_training/datasets/balanced_vulnerabilities.json", help="Путь к итоговому сбалансированному датасету")
    parser.add_argument("--skip-github", action="store_true", help="Пропустить сбор данных из GitHub и использовать только сгенерированные данные")
    
    args = parser.parse_args()
    
    # Проверка GITHUB_TOKEN
    if not args.skip_github and not os.environ.get("GITHUB_TOKEN"):
        logger.error("GITHUB_TOKEN не установлен. Пожалуйста, установите переменную окружения:")
        logger.error("export GITHUB_TOKEN=ваш_токен_здесь")
        logger.error("Токен можно получить по адресу: https://github.com/settings/tokens (требуются права public_repo)")
        logger.info("Используйте флаг --skip-github для пропуска сбора данных из GitHub и генерации только синтетических данных")
        if not args.skip_github:
            exit(1)
    
    # 1. Сбор SQL-инъекций
    sql_examples = []
    if not args.skip_github:
        logger.info("🔍 Сбор SQL-инъекций из GitHub...")
        sql_examples = collect_sql_injections(max_repos=args.max_repos, output_dir=args.output_dir)
    else:
        logger.info("⏭️  Пропуск сбора данных из GitHub (флаг --skip-github)")
    
    # Если не удалось собрать достаточно данных из GitHub, генерируем синтетические
    if len(sql_examples) < args.dangerous_count and args.skip_github:
        logger.info("🆕 Генерация синтетических SQL-инъекций...")
        sql_examples = _generate_synthetic_sql_examples(args.dangerous_count)
    
    # 2. Генерация опасных функций
    logger.info("🆕 Генерация примеров опасных функций...")
    dangerous_examples = generate_dangerous_functions(count=max(len(sql_examples), args.dangerous_count), output_dir=args.output_dir)
    
    # 3. Балансировка датасета
    logger.info("⚖️  Балансировка датасета...")
    sql_file = os.path.join(args.output_dir, "sql_injections.json")
    dangerous_file = os.path.join(args.output_dir, "dangerous_functions.json")
    
    balance_dataset(
        sql_file=sql_file,
        dangerous_file=dangerous_file,
        output_file=args.final_output,
        test_split=args.test_split
    )
    
    # 4. Проверка баланса
    logger.info("✅ Проверка итогового баланса датасета...")
    check_class_balance(args.final_output)
    
    logger.info("🎉 Датасет успешно собран, сгенерирован и сбалансирован!")
    logger.info(f"Итоговый файл сохранен: {args.final_output}")

if __name__ == "__main__":
    main()