import re
from datetime import datetime, timedelta

LOG_FILE = 'monitor2.log'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'  # формат даты в начале каждой записи (без миллисекунд)

def parse_log_date(line):
    """
    Извлекает дату из строки лога.
    Предполагается, что строка начинается с даты в формате 'YYYY-MM-DD HH:MM:SS,...'
    """
    match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
    if match:
        date_str = match.group(1)
        try:
            return datetime.strptime(date_str, DATE_FORMAT)
        except ValueError:
            return None
    return None

def clean_log_file(file_path, days_to_keep=45):
    cutoff_date = datetime.now() - timedelta(days=days_to_keep)
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    cleaned_lines = []
    for line in lines:
        log_date = parse_log_date(line)
        if log_date is None:
            # Если не удалось распарсить дату, сохраняем строку (чтобы не потерять важные данные)
            cleaned_lines.append(line)
        else:
            if log_date >= cutoff_date:
                cleaned_lines.append(line)

    # Перезаписываем файл очищенными строками
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(cleaned_lines)

    print(f"Очистка завершена. Удалено записей старше {days_to_keep} дней.")

if __name__ == '__main__':
    clean_log_file(LOG_FILE)
