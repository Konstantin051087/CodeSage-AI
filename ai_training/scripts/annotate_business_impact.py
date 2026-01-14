# Файл: ai_training/scripts/annotate_business_impact.py
import json
import random
from pathlib import Path

# Шаблоны бизнес-воздействия для разных типов уязвимостей
BUSINESS_IMPACT_TEMPLATES = {
    "sql_injection": [
        "Risk of full database leak → GDPR fines up to €20M",
        "Potential data breach exposing customer information → loss of trust and revenue",
        "Unauthorized access to sensitive data → regulatory penalties and legal costs"
    ],
    "dangerous_function": [
        "Remote code execution → server takeover",
        "Arbitrary code execution → complete system compromise",
        "Malicious payload execution → data theft and service disruption"
    ],
    "xss": [
        "Session hijacking → unauthorized access to user accounts",
        "Client-side script injection → credential theft and fraud"
    ],
    "path_traversal": [
        "Unauthorized file access → intellectual property theft",
        "Sensitive file exposure → competitive disadvantage and data leaks"
    ]
}

# Контекст компаний для аннотации
INDUSTRY_CONTEXTS = {
    "fintech": {
        "company_size": "startup",
        "industry": "fintech",
        "estimated_cost_per_incident": "$50,000",
        "regulatory_risks": ["GDPR", "PCI-DSS", "SOX"]
    },
    "healthcare": {
        "company_size": "enterprise",
        "industry": "healthcare",
        "estimated_cost_per_incident": "$250,000",
        "regulatory_risks": ["HIPAA", "GDPR"]
    },
    "ecommerce": {
        "company_size": "medium",
        "industry": "ecommerce",
        "estimated_cost_per_incident": "$100,000",
        "regulatory_risks": ["PCI-DSS", "GDPR"]
    },
    "general": {
        "company_size": "small",
        "industry": "general",
        "estimated_cost_per_incident": "$25,000",
        "regulatory_risks": ["GDPR"]
    }
}

def annotate_dataset(input_file, output_file):
    """Аннотирует собранные данные бизнес-воздействием"""
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    annotated_data = []
    
    for item in data:
        vuln_type = item["vulnerability_type"]
        
        # Выбираем случайный шаблон бизнес-воздействия
        if vuln_type in BUSINESS_IMPACT_TEMPLATES:
            item["business_impact"] = random.choice(BUSINESS_IMPACT_TEMPLATES[vuln_type])
        else:
            item["business_impact"] = "Security vulnerability with potential business impact"
        
        # Генерируем рекомендацию по исправлению
        if vuln_type == "sql_injection":
            item["fix_recommendation"] = "Use parameterized queries with placeholders"
        elif vuln_type == "dangerous_function":
            item["fix_recommendation"] = "Replace with safe alternatives (e.g., json.loads instead of pickle.loads)"
        else:
            item["fix_recommendation"] = "Apply security best practices for this vulnerability type"
        
        # Добавляем контекст компании
        industries = list(INDUSTRY_CONTEXTS.keys())
        selected_industry = random.choice(industries)
        item["business_context"] = INDUSTRY_CONTEXTS[selected_industry]
        
        annotated_data.append(item)
    
    # Сохраняем аннотированный датасет
    with open(output_file, 'w') as f:
        json.dump(annotated_data, f, indent=2)
    
    print(f"Аннотировано {len(annotated_data)} примеров")
    print(f"Распределение типов уязвимостей:")
    type_counts = {}
    for item in annotated_data:
        vuln_type = item["vulnerability_type"]
        type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
    
    for vuln_type, count in type_counts.items():
        print(f"- {vuln_type}: {count} примеров")
    
    return annotated_data

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="ai_training/datasets/vulnerabilities.json", help="Входной файл с неаннотированными данными")
    parser.add_argument("--output", default="ai_training/datasets/annotated_vulnerabilities.json", help="Выходной файл с аннотированными данными")
    args = parser.parse_args()
    
    annotate_dataset(args.input, args.output)