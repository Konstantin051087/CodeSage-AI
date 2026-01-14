# Файл: ai_training/scripts/check_class_balance.py
import json

def check_class_balance(dataset_file):
    """Проверяет баланс классов в датасете"""
    with open(dataset_file, 'r') as f:
        data = json.load(f)
    
    type_counts = {}
    for item in data:
        vuln_type = item.get("vulnerability_type", "unknown")
        type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
    
    print("Распределение типов уязвимостей:")
    total = sum(type_counts.values())
    for vuln_type, count in type_counts.items():
        percentage = (count / total) * 100
        print(f"- {vuln_type}: {count} ({percentage:.1f}%)")
    
    # Проверяем баланс
    if max(type_counts.values()) / min(type_counts.values()) > 3:
        print("⚠️ Предупреждение: датасет несбалансирован. Рассмотрите возможность аугментации или сбора дополнительных данных.")
    else:
        print("✅ Датасет сбалансирован по классам")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="ai_training/datasets/annotated_vulnerabilities.json", help="Путь к датасету")
    args = parser.parse_args()
    
    check_class_balance(args.dataset)