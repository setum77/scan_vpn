#!/bin/bash

# Переход в директорию проекта (!!!заменить user-name на свое)
cd /home/user-name/scan_vpn

# Если не используем uv, то активируем виртуальное окружение (раскомитить две строки ниже, 
# поправивить название папки .venv, если нужно,  
# закомитить строку "/home/user-name/.local/bin/uv run -- python flask_db.py") 
# source .venv/bin/activate
# exec python -m scan_vpn.flask_db

# Запуск приложения через uv (!!!заменить user-name на свое)
/home/user-name/.local/bin/uv run -- python flask_db.py
