# Файл: core/ai/model_loader.py
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class AIModelLoader:
    """Загружает и управляет AI-моделью для генерации бизнес-объяснений"""
    
    DEFAULT_MODEL_PATH = "CodeSage-AI/business-impact-explainer"
    
    def __init__(self, model_path=None, device=None):
        """
        Инициализирует загрузчик модели
        
        Args:
            model_path (str): Путь к модели (локальный или Hugging Face Hub)
            device (str): Устройство для инференса ('cpu', 'cuda', 'mps')
        """
        self.model_path = model_path or self.DEFAULT_MODEL_PATH
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        
        # Проверяем, является ли путь локальным файлом
        self.is_local = os.path.exists(self.model_path)
        
        logger.info(f"Инициализация AI-модели: путь={self.model_path}, устройство={self.device}")
        
        self.tokenizer = None
        self.model = None
        self._load_model()
    
    def _load_model(self):
        """Загружает модель и токенизатор"""
        try:
            logger.info("Загрузка токенизатора...")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            logger.info("Загрузка модели...")
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                torch_dtype=torch.float16 if self.device != "cpu" else torch.float32
            )
            
            # Перемещаем модель на указанное устройство
            self.model.to(self.device)
            self.model.eval()
            
            logger.info(f"Модель успешно загружена на {self.device}")
            
        except Exception as e:
            logger.error(f"Ошибка при загрузке модели: {str(e)}")
            raise
    
    def generate_explanation(self, vulnerability_type, code_snippet, max_new_tokens=200):
        """
        Генерирует бизнес-объяснение для уязвимости
        
        Args:
            vulnerability_type (str): Тип уязвимости
            code_snippet (str): Фрагмент кода с уязвимостью
            max_new_tokens (int): Максимальное количество генерируемых токенов
            
        Returns:
            str: Сгенерированное объяснение
        """
        try:
            # Формируем промпт
            prompt = f"""Объясни эту уязвимость с точки зрения бизнеса:

Тип: {vulnerability_type}
Код: {code_snippet}

Твой ответ:"""
            
            # Токенизация
            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                truncation=True,
                max_length=1024
            ).to(self.device)
            
            # Генерация
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=max_new_tokens,
                    temperature=0.7,
                    top_p=0.9,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            # Декодирование
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            explanation = response.split("Твой ответ:")[-1].strip()
            
            # Очистка от артефактов
            if explanation.startswith('"') and explanation.endswith('"'):
                explanation = explanation[1:-1]
            
            return explanation
            
        except Exception as e:
            logger.error(f"Ошибка при генерации объяснения: {str(e)}")
            return None
    
    def extract_business_keywords(self, explanation):
        """
        Извлекает ключевые слова для бизнес-воздействия
        
        Args:
            explanation (str): Объяснение от модели
            
        Returns:
            list: Список ключевых слов
        """
        if not explanation:
            return []
        
        keywords = []
        explanation_lower = explanation.lower()
        
        # Шаблоны ключевых слов
        business_keywords = {
            "💰 GDPR fines": ["gdpr", "штраф", "fines", "compliance"],
            "🚨 Data breach": ["утечка", "leak", "breach", "exposure"],
            "🔥 Server takeover": ["hijack", "takeover", "compromise", "server"],
            "💸 Financial loss": ["financial", "loss", "cost", "money", "revenue"],
            "⚖️ Legal risk": ["legal", "lawsuit", "court", "regulatory"],
            "📉 Reputation damage": ["reputation", "trust", "brand", "image"]
        }
        
        for keyword, patterns in business_keywords.items():
            if any(pattern in explanation_lower for pattern in patterns):
                keywords.append(keyword)
        
        return keywords
    
    def fallback_explanation(self, vulnerability_type):
        """
        Генерирует стандартное объяснение при ошибке ИИ
        
        Args:
            vulnerability_type (str): Тип уязвимости
            
        Returns:
            str: Стандартное объяснение
        """
        fallbacks = {
            "sql_injection": "Risk of full database leak → GDPR fines up to €20M",
            "dangerous_function": "Remote code execution → server takeover",
            "xss": "Session hijacking → unauthorized access to user accounts",
            "path_traversal": "Unauthorized file access → intellectual property theft"
        }
        
        return fallbacks.get(vulnerability_type, "Potential security risk with business impact")