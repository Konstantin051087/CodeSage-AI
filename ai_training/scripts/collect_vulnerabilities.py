import json
import os
from github import Github
from github.Auth import Token
from tqdm import tqdm
import time
import logging
import re
from typing import Dict, List, Optional

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def collect_vulnerabilities(output_file="ai_training/datasets/vulnerabilities.json", max_repos=5):
    """
    Собирает примеры уязвимостей с GitHub с более гибкой логикой
    
    Args:
        output_file: Путь для сохранения результатов
        max_repos: Максимальное количество репозиториев для анализа
    """
    # Получение токена GitHub
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        raise ValueError("GITHUB_TOKEN не установлен в переменных окружения. "
                         "Пожалуйста, установите его с помощью: export GITHUB_TOKEN=ваш_токен")
    
    # Аутентификация в GitHub API
    auth = Token(github_token)
    g = Github(auth=auth)
    
    # Проверка подключения и лимитов
    try:
        user = g.get_user()
        rate_limit = g.get_rate_limit()
        logger.info(f"Подключено к GitHub API как пользователь: {user.login}")
        # 🔴 ИСПРАВЛЕНО: Используем rate_limit.resources вместо rate_limit.core в новых версиях PyGithub
        logger.info(f"Текущие лимиты: core: {rate_limit.resources.core.remaining}/{rate_limit.resources.core.limit}, "
                   f"search: {rate_limit.resources.search.remaining}/{rate_limit.resources.search.limit}")
    except Exception as e:
        logger.error(f"Ошибка подключения к GitHub API: {str(e)}")
        raise
    
    logger.info("Начало сбора примеров уязвимостей...")
    
    # Запросы для поиска уязвимостей
    queries = [
        "SQL injection fix language:python",
        "pickle.loads security fix language:python",
        "eval security vulnerability fix language:python",
        "dangerous function security fix language:python"
    ]
    
    all_examples = []
    repo_count = 0
    
    for query in queries:
        if repo_count >= max_repos:
            break
            
        logger.info(f"Поиск репозиториев по запросу: '{query}'")
        
        try:
            # Поиск репозиториев с сортировкой по количеству звезд
            repos = g.search_repositories(query, sort="stars", order="desc")
            
            # Итерация по репозиториям с ограничением
            for repo in tqdm(repos, desc=f"Обработка репозиториев по запросу '{query}'"):
                if repo_count >= max_repos:
                    break
                
                try:
                    logger.debug(f"Анализ репозитория: {repo.full_name}")
                    
                    # Попытка найти файлы с уязвимостями несколькими способами
                    examples = _find_vulnerability_examples(repo)
                    
                    if examples:
                        all_examples.extend(examples)
                        logger.info(f"Найдено {len(examples)} примеров уязвимостей в репозитории {repo.full_name}")
                    else:
                        logger.warning(f"Не найдено примеров уязвимостей в репозитории {repo.full_name}")
                    
                    repo_count += 1
                    
                    # Уважаем лимиты API
                    time.sleep(2)
                    
                except Exception as e:
                    logger.error(f"Ошибка при обработке репозитория {repo.full_name}: {str(e)}")
                    continue
                    
        except Exception as e:
            logger.error(f"Ошибка при поиске репозиториев по запросу '{query}': {str(e)}")
            continue
    
    # Проверка результатов
    if not all_examples:
        logger.warning("Не удалось собрать примеры уязвимостей. "
                      "Попробуйте увеличить количество репозиториев или изменить запросы поиска.")
        # Создаем пример данных для продолжения работы
        all_examples = _create_sample_vulnerabilities()
        logger.info("Созданы образцовые данные для продолжения работы")
    
    # Сохранение результатов
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_examples, f, indent=2, ensure_ascii=False)
    
    logger.info(f"✅ Успешно собрано {len(all_examples)} примеров уязвимостей")
    logger.info(f"Данные сохранены в: {output_file}")
    
    return all_examples

def _find_vulnerability_examples(repo) -> List[Dict]:
    """
    Находит примеры уязвимостей в репозитории несколькими способами:
    1. Поиск файлов с известными шаблонами уязвимостей
    2. Анализ содержимого README и документации
    3. Анализ issue с ключевыми словами
    """
    examples = []
    processed_paths = set()
    
    try:
        # 1. Поиск в корневой директории и поддиректориях
        contents = repo.get_contents("")
        files_to_check = []
        
        # Сначала собираем все Python файлы
        while contents:
            file_content = contents.pop(0)
            if file_content.path in processed_paths:
                continue
                
            processed_paths.add(file_content.path)
            
            if file_content.type == "dir" and len(contents) < 50:  # Ограничиваем глубину поиска
                try:
                    contents.extend(repo.get_contents(file_content.path))
                except Exception as e:
                    continue
            elif file_content.type == "file" and file_content.path.endswith(".py"):
                files_to_check.append(file_content)
        
        # 2. Анализ Python файлов на предмет известных шаблонов уязвимостей
        vulnerability_patterns = {
            "sql_injection": [
                r'cursor\.execute\s*\(\s*f["\'].*\{.*\}.*["\']\s*\)',
                r'cursor\.execute\s*\(\s*.*\+.*\)',
                r'execute\s*\(\s*.*\%.*\)'
            ],
            "dangerous_function": [
                r'pickle\.loads\s*\(',
                r'eval\s*\(',
                r'exec\s*\(',
                r'jsonpickle\.decode\s*\('
            ]
        }
        
        for file in files_to_check[:10]:  # Ограничиваем количество проверяемых файлов
            try:
                file_content = repo.get_contents(file.path).decoded_content.decode('utf-8')
                lines = file_content.split('\n')
                
                # Проверка каждой строки на наличие паттернов уязвимостей
                for line_num, line in enumerate(lines, 1):
                    for vuln_type, patterns in vulnerability_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, line):
                                # Создаем пример уязвимости
                                context_lines = max(0, line_num - 3), min(len(lines), line_num + 3)
                                code_context = "\n".join([
                                    f"{i+1}: {lines[i]}" if i+1 != line_num else f"{i+1}: >>> {lines[i].strip()} <<<"
                                    for i in range(context_lines[0], context_lines[1])
                                ])
                                
                                example = {
                                    "repo": repo.full_name,
                                    "file_path": file.path,
                                    "line_number": line_num,
                                    "vulnerability_type": vuln_type,
                                    "code_snippet": code_context,
                                    "code_before": code_context,
                                    "code_after": _get_fixed_code_example(vuln_type, line),
                                    "business_impact": _get_business_impact(vuln_type),
                                    "fix_recommendation": _get_fix_recommendation(vuln_type),
                                    "industry_context": "general"
                                }
                                examples.append(example)
                                logger.debug(f"Найдена уязвимость {vuln_type} в {repo.full_name}/{file.path}:{line_num}")
            
            except Exception as e:
                continue
        
        # 3. Если не нашли в файлах, проверяем issues с тегами безопасности
        if not examples:
            try:
                issues = repo.get_issues(state="closed", labels=["security", "bug", "vulnerability"])
                for issue in issues[:5]:  # Проверяем только первые 5 issues
                    title_lower = issue.title.lower()
                    body_lower = issue.body.lower() if issue.body else ""
                    
                    if "sql injection" in title_lower or "sql injection" in body_lower:
                        examples.append(_create_issue_based_example(repo, issue, "sql_injection"))
                    elif "pickle" in title_lower or "pickle" in body_lower or "eval" in title_lower or "eval" in body_lower:
                        examples.append(_create_issue_based_example(repo, issue, "dangerous_function"))
            except Exception as e:
                pass
        
    except Exception as e:
        logger.debug(f"Не удалось найти примеры в репозитории {repo.full_name}: {str(e)}")
    
    return examples[:3]  # Ограничиваем до 3 примеров на репозиторий

def _get_fixed_code_example(vuln_type: str, vulnerable_line: str) -> str:
    """Генерирует пример исправленного кода для уязвимости"""
    if vuln_type == "sql_injection":
        return "cursor.execute(\"SELECT * FROM users WHERE name = %s\", (name,))"
    elif vuln_type == "dangerous_function":
        if "pickle.loads" in vulnerable_line:
            return "import json\nresult = json.loads(data)"
        elif "eval" in vulnerable_line:
            return "import ast\nresult = ast.literal_eval(input_str)"
    return "# Безопасная альтернатива зависит от контекста"

def _get_business_impact(vuln_type: str) -> str:
    """Возвращает бизнес-воздействие для типа уязвимости"""
    impacts = {
        "sql_injection": "Risk of full database leak → GDPR fines up to €20M",
        "dangerous_function": "Remote code execution → server takeover"
    }
    return impacts.get(vuln_type, "Security risk with potential business impact")

def _get_fix_recommendation(vuln_type: str) -> str:
    """Возвращает рекомендации по исправлению"""
    recommendations = {
        "sql_injection": "Use parameterized queries with placeholders",
        "dangerous_function": "Replace with safe alternatives (e.g., json.loads instead of pickle.loads)"
    }
    return recommendations.get(vuln_type, "Apply security best practices for this vulnerability type")

def _create_issue_based_example(repo, issue, vuln_type: str) -> Dict:
    """Создает пример уязвимости на основе issue"""
    return {
        "repo": repo.full_name,
        "issue_url": issue.html_url,
        "issue_title": issue.title,
        "vulnerability_type": vuln_type,
        "code_before": "N/A - Описано в issue",
        "code_after": "N/A - Описано в issue",
        "business_impact": _get_business_impact(vuln_type),
        "fix_recommendation": _get_fix_recommendation(vuln_type),
        "industry_context": "general"
    }

def _create_sample_vulnerabilities() -> List[Dict]:
    """Создает примеры уязвимостей для демонстрации, если не удалось собрать реальные данные"""
    return [
        {
            "repo": "example/vulnerable-app",
            "file_path": "app.py",
            "line_number": 24,
            "vulnerability_type": "sql_injection",
            "code_snippet": "22: def get_user(name):\n23:     # Уязвимый код\n24: >>> cursor.execute(f\"SELECT * FROM users WHERE name = {name}\") <<<",
            "code_before": "cursor.execute(f\"SELECT * FROM users WHERE name = {name}\")",
            "code_after": "cursor.execute(\"SELECT * FROM users WHERE name = %s\", (name,))",
            "business_impact": "Risk of full database leak → GDPR fines up to €20M",
            "fix_recommendation": "Use parameterized queries with placeholders",
            "industry_context": "fintech"
        },
        {
            "repo": "example/data-processor",
            "file_path": "utils.py",
            "line_number": 15,
            "vulnerability_type": "dangerous_function",
            "code_snippet": "14: import pickle\n15: >>> data = pickle.loads(user_input) <<<",
            "code_before": "data = pickle.loads(user_input)",
            "code_after": "import json\ndata = json.loads(user_input)",
            "business_impact": "Remote code execution → server takeover",
            "fix_recommendation": "Replace with safe alternatives (e.g., json.loads instead of pickle.loads)",
            "industry_context": "healthcare"
        }
    ]

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Сбор примеров уязвимостей с GitHub')
    parser.add_argument("--output", default="ai_training/datasets/vulnerabilities.json", 
                       help="Путь к выходному файлу")
    parser.add_argument("--max-repos", type=int, default=5, 
                       help="Максимальное количество репозиториев для анализа")
    
    args = parser.parse_args()
    
    # Проверка GITHUB_TOKEN
    if not os.environ.get("GITHUB_TOKEN"):
        logger.error("GITHUB_TOKEN не установлен. Пожалуйста, установите переменную окружения:")
        logger.error("export GITHUB_TOKEN=ваш_токен_здесь")
        logger.error("Токен можно получить по адресу: https://github.com/settings/tokens   (требуются права public_repo)")
        exit(1)
    
    collect_vulnerabilities(args.output, args.max_repos)