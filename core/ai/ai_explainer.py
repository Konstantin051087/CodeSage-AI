# Файл: core/ai/ai_explainer.py
import os
import sqlite3
import time
import json
import logging
from pathlib import Path
from .model_loader import AIModelLoader

logger = logging.getLogger(__name__)

class AICache:
    """Кэширование результатов ИИ для ускорения повторных запросов"""
    
    def __init__(self, cache_path="ai_cache.db"):
        self.cache_path = cache_path
        self._init_db()
    
    def _init_db(self):
        """Инициализирует базу данных кэша"""
        try:
            conn = sqlite3.connect(self.cache_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS explanations (
                    vuln_type TEXT NOT NULL,
                    code_hash TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    keywords TEXT,
                    timestamp REAL NOT NULL,
                    PRIMARY KEY (vuln_type, code_hash)
                )
            ''')
            conn.commit()
            conn.close()
            logger.info(f"База данных кэша инициализирована: {self.cache_path}")
        except Exception as e:
            logger.error(f"Ошибка при инициализации БД кэша: {str(e)}")
            raise
    
    def get(self, vuln_type, code_hash):
        """Получает объяснение из кэша"""
        try:
            conn = sqlite3.connect(self.cache_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT explanation, keywords FROM explanations WHERE vuln_type = ? AND code_hash = ? AND timestamp > ?",
                (vuln_type, code_hash, time.time() - 30*24*3600)  # Кэш живет 30 дней
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                explanation, keywords_str = result
                keywords = json.loads(keywords_str) if keywords_str else []
                return {
                    "explanation": explanation,
                    "keywords": keywords
                }
            return None
        except Exception as e:
            logger.error(f"Ошибка при чтении из кэша: {str(e)}")
            return None
    
    def set(self, vuln_type, code_hash, explanation, keywords=None):
        """Сохраняет объяснение в кэш"""
        try:
            conn = sqlite3.connect(self.cache_path)
            cursor = conn.cursor()
            keywords_str = json.dumps(keywords) if keywords else None
            
            cursor.execute(
                "INSERT OR REPLACE INTO explanations (vuln_type, code_hash, explanation, keywords, timestamp) VALUES (?, ?, ?, ?, ?)",
                (vuln_type, code_hash, explanation, keywords_str, time.time())
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Ошибка при записи в кэш: {str(e)}")
            return False

class AIExplainer:
    """Основной класс для генерации бизнес-объяснений уязвимостей"""
    
    def __init__(self, model_path=None, use_cache=True, use_ai=True):
        """
        Инициализирует AIExplainer
        
        Args:
            model_path (str): Путь к модели
            use_cache (bool): Использовать кэширование
            use_ai (bool): Использовать ИИ (если False, использует шаблоны)
        """
        self.use_ai = use_ai
        self.use_cache = use_cache
        
        if use_cache:
            self.cache = AICache()
        
        if use_ai:
            try:
                self.model_loader = AIModelLoader(model_path)
                logger.info("AIExplainer инициализирован с моделью ИИ")
            except Exception as e:
                logger.warning(f"Не удалось загрузить модель ИИ: {str(e)}. Используется fallback-режим.")
                self.use_ai = False
    
    def _generate_code_hash(self, code_snippet):
        """Генерирует хэш для кэширования"""
        import hashlib
        return hashlib.md5(code_snippet.encode()).hexdigest()
    
    def explain_vulnerability(self, vulnerability_type, code_snippet):
        """
        Генерирует бизнес-объяснение для уязвимости
        
        Args:
            vulnerability_type (str): Тип уязвимости
            code_snippet (str): Фрагмент кода с уязвимостью
            
        Returns:
            dict: Словарь с объяснением и ключевыми словами
        """
        # Генерируем хэш кода для кэширования
        code_hash = self._generate_code_hash(code_snippet)
        
        # Проверяем кэш
        if self.use_cache:
            cached_result = self.cache.get(vulnerability_type, code_hash)
            if cached_result:
                logger.debug("Результат получен из кэша")
                return cached_result
        
        # Генерируем объяснение
        if self.use_ai:
            try:
                explanation = self.model_loader.generate_explanation(vulnerability_type, code_snippet)
                keywords = self.model_loader.extract_business_keywords(explanation) if explanation else []
                
                if not explanation:  # Если ИИ не сгенерировал объяснение
                    explanation = self.model_loader.fallback_explanation(vulnerability_type)
                    keywords = self._extract_keywords_from_fallback(explanation)
            except Exception as e:
                logger.error(f"Ошибка при генерации объяснения ИИ: {str(e)}")
                explanation = self.model_loader.fallback_explanation(vulnerability_type)
                keywords = self._extract_keywords_from_fallback(explanation)
        else:
            explanation = self.model_loader.fallback_explanation(vulnerability_type) if hasattr(self, 'model_loader') else self._template_explanation(vulnerability_type)
            keywords = self._extract_keywords_from_fallback(explanation)
        
        # Сохраняем в кэш
        if self.use_cache:
            self.cache.set(vulnerability_type, code_hash, explanation, keywords)
        
        return {
            "explanation": explanation,
            "keywords": keywords,
            "ai_generated": self.use_ai
        }
    
    def _template_explanation(self, vulnerability_type):
        """Генерирует объяснение из шаблонов без ИИ"""
        templates = {
            "sql_injection": "Risk of full database leak → GDPR fines up to €20M. Unprotected SQL queries can expose all user data and lead to severe regulatory penalties.",
            "dangerous_function": "Remote code execution → server takeover. Functions like eval() or pickle.loads() can execute arbitrary code, giving attackers full control of your systems.",
            "xss": "Session hijacking → unauthorized access to user accounts. Cross-site scripting allows attackers to steal user sessions and impersonate legitimate users.",
            "path_traversal": "Unauthorized file access → intellectual property theft. Path traversal vulnerabilities enable attackers to read sensitive files outside intended directories."
        }
        return templates.get(vulnerability_type, f"This vulnerability poses a security risk that could impact your business operations.")
    
    def _extract_keywords_from_fallback(self, explanation):
        """Извлекает ключевые слова из стандартного объяснения"""
        return self.model_loader.extract_business_keywords(explanation) if hasattr(self, 'model_loader') else []
    
    def get_business_impact_score(self, vulnerability_type):
        """
        Возвращает оценку бизнес-воздействия (1-10)
        
        Args:
            vulnerability_type (str): Тип уязвимости
            
        Returns:
            int: Оценка воздействия
        """
        scores = {
            "sql_injection": 9,
            "dangerous_function": 8,
            "xss": 6,
            "path_traversal": 7
        }
        return scores.get(vulnerability_type, 5)