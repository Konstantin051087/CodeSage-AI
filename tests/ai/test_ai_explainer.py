# Файл: tests/ai/test_ai_explainer.py
import pytest
import os
from core.ai.ai_explainer import AIExplainer, AICache
from core.ai.model_loader import AIModelLoader
import tempfile
import json

# Пропускаем тесты ИИ если не установлены зависимости или нет переменной окружения
@pytest.mark.skipif(os.getenv("SKIP_AI_TESTS", "1") == "1", reason="Skipping AI tests to save resources")
class TestAIExplainer:
    def test_ai_explainer_initialization(self):
        """Тестирует инициализацию AIExplainer"""
        explainer = AIExplainer(use_ai=False)
        assert explainer.use_ai == False
        
        # Тестируем инициализацию с кэшем
        explainer_with_cache = AIExplainer(use_ai=False, use_cache=True)
        assert explainer_with_cache.use_cache == True
    
    def test_business_keywords_extraction(self):
        """Тестирует извлечение ключевых слов из объяснений"""
        explainer = AIExplainer(use_ai=False)
        
        # Тестовые объяснения
        test_cases = [
            ("GDPR fines up to €20M for data breach", ["💰 GDPR fines", "🚨 Data breach"]),
            ("Remote code execution can lead to server takeover", ["🔥 Server takeover"]),
            ("This vulnerability might cause financial losses", ["💸 Financial loss"]),
            ("Legal implications include lawsuits and regulatory action", ["⚖️ Legal risk"]),
            ("Customer trust will be damaged after a breach", ["📉 Reputation damage"])
        ]
        
        for explanation, expected_keywords in test_cases:
            keywords = explainer.model_loader.extract_business_keywords(explanation) if hasattr(explainer, 'model_loader') else []
            assert all(keyword in keywords for keyword in expected_keywords)
    
    def test_cache_mechanism(self):
        """Тестирует механизм кэширования"""
        # Создаем временный файл для БД кэша
        with tempfile.NamedTemporaryFile(delete=False) as temp_db:
            temp_db_path = temp_db.name
        
        try:
            # Инициализируем кэш
            cache = AICache(cache_path=temp_db_path)
            
            # Тестируем запись и чтение
            vuln_type = "sql_injection"
            code_hash = "test_hash"
            explanation = "Risk of full database leak → GDPR fines up to €20M"
            keywords = ["💰 GDPR fines", "🚨 Data breach"]
            
            # Запись в кэш
            assert cache.set(vuln_type, code_hash, explanation, keywords)
            
            # Чтение из кэша
            result = cache.get(vuln_type, code_hash)
            assert result is not None
            assert result["explanation"] == explanation
            assert result["keywords"] == keywords
            
            # Тестируем устаревание кэша
            import time
            time.sleep(1)  # Ждем немного
            
            # Читаем снова (должно работать)
            result2 = cache.get(vuln_type, code_hash)
            assert result2 is not None
            
        finally:
            # Удаляем временный файл
            if os.path.exists(temp_db_path):
                os.unlink(temp_db_path)
    
    def test_fallback_explanation(self):
        """Тестирует fallback-объяснения при ошибке ИИ"""
        explainer = AIExplainer(use_ai=False)
        
        # Проверяем объяснения для разных типов уязвимостей
        test_cases = [
            ("sql_injection", "Risk of full database leak → GDPR fines up to €20M"),
            ("dangerous_function", "Remote code execution → server takeover"),
            ("xss", "Session hijacking → unauthorized access to user accounts"),
            ("path_traversal", "Unauthorized file access → intellectual property theft"),
            ("unknown_vuln", "This vulnerability poses a security risk that could impact your business operations")
        ]
        
        for vuln_type, expected_text in test_cases:
            explanation = explainer._template_explanation(vuln_type)
            assert expected_text in explanation
    
    @pytest.mark.skipif(not os.getenv("RUN_AI_TESTS", "0") == "1", reason="AI tests require explicit enablement")
    def test_ai_explanation_generation(self):
        """Тестирует генерацию объяснений с использованием реальной модели ИИ"""
        # Этот тест запускается только при явном разрешении из-за ресурсоемкости
        explainer = AIExplainer(use_ai=True)
        
        # Тестируем объяснение для SQL-инъекции
        vuln_type = "sql_injection"
        code_snippet = "cursor.execute(f\"SELECT * FROM users WHERE name = {user_input}\")"
        
        result = explainer.explain_vulnerability(vuln_type, code_snippet)
        assert result is not None
        assert "explanation" in result
        assert isinstance(result["explanation"], str)
        assert len(result["explanation"]) > 10  # Минимальная длина объяснения
        
        # Проверяем наличие ключевых слов
        assert "keywords" in result
        assert isinstance(result["keywords"], list)