# Скрипт запускающий фласк сервер 
# Для запуска в cron нужна команда
# /var/www/monitor_lan/myenv/bin/python /var/www/monitor_lan/flask_run.py
# первый путь до папки venv c ярлыком на python
# второй путь до этого файла

from datetime import datetime
import os
import sys
import time
import logging
import subprocess
from flask import Flask, render_template, url_for, request, flash, Response, jsonify, redirect

from flask_sqlalchemy import SQLAlchemy
from collections import defaultdict
from datetime import datetime, timedelta
from flask_apscheduler import APScheduler
from .clean_logs import clean_log_file


work_dir = os.path.dirname(os.path.abspath(__file__))
devices = os.path.join(work_dir, 'devices.yaml')
devices_w = os.path.join(work_dir, 'devices_w.yaml')
scan_lan = os.path.join(work_dir, 'scan_to_db.py')
flask_log = os.path.join(work_dir, 'flasklog.log')
monitor_log = os.path.join(work_dir, 'monitor2.log')
python_executable = sys.executable  # например, /path/to/myenv/bin/python
db_path = os.path.join(work_dir, 'routers.db')
scan_to_db = os.path.join(work_dir, 'scan_to_db.py')
lines_ = [] # Список для будущей сборки текста письма
lines_m = [] # Список строк для будущей сборки текста письма по мобильным роутерам
f_lines_m = os.path.join(work_dir, 'lines_m.txt') # Файл для записи статусов Пробоксов и последующей отправки 1 раз в день

class Config:
    SCHEDULER_API_ENABLED = True
    SECRET_KEY = 'kedr2025'
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


app = Flask(__name__)
app.config.from_object(Config())

db = SQLAlchemy(app)
scheduler = APScheduler()

logging.basicConfig(
    filename= flask_log,
    encoding='UTF-8',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)

scheduler_logger = logging.getLogger('apscheduler')
scheduler_logger.setLevel(logging.DEBUG)

class Router(db.Model):
    __tablename__ = 'routers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    ip1 = db.Column(db.String)
    ip2 = db.Column(db.String)
    ip3 = db.Column(db.String)
    dns = db.Column(db.String)
    lan1 = db.Column(db.Integer)
    lan2 = db.Column(db.Integer)
    lan3 = db.Column(db.Integer)
    lan4 = db.Column(db.Integer)
    lan4err = db.Column(db.String)
    model = db.Column(db.String)
    mobil = db.Column(db.Integer)

    behind_devices = db.relationship('Device', backref='router', lazy=True, foreign_keys='Device.router_id')
    pritok_devices = db.relationship('Device', backref='pritok_router', lazy=True, foreign_keys='Device.pritok_router_id')

    def __repr__(self):
        return f'<Router {self.name}>'

class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String)
    name = db.Column(db.String, nullable=False)
    lan = db.Column(db.Integer)
    router_id = db.Column(db.Integer, db.ForeignKey('routers.id'))
    pritok_router_id = db.Column(db.Integer, db.ForeignKey('routers.id'))

    def __repr__(self):
        return f'<Device {self.name}>'

class ScanLog(db.Model):
    __tablename__ = 'scan_logs'
    id = db.Column(db.Integer, primary_key=True)
    scan_datetime = db.Column(db.DateTime, default=datetime.utcnow)
    router_id = db.Column(db.Integer, db.ForeignKey('routers.id'), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=True)
    ip = db.Column(db.String)
    status = db.Column(db.Integer)  # 0 or 1
    dns = db.Column(db.String)
    lan4err = db.Column(db.String)

    def __repr__(self):
        return f'<Scanlog {self.status}>'

menu = [
    {'name': "Главная", 'url': 'index1'},
    {'name': "Логи", 'url': 'logs'},
    {'name': "Инструменты", 'url': 'tools'},
    {'name': "Обратная связь", 'url': 'contact'}
]

def format_size(bytes_size):
    if bytes_size is None:
        return "Размер неизвестен"
    units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']
    size = float(bytes_size)
    for unit in units:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} ПБ"

@app.route('/')
@app.route('/index1')
def index():
    # Получаем дату из параметра запроса, если есть
    date_str = request.args.get('date')
    if date_str:
        # Если дата выбрана, анализируем её
        try:
            selected_date = datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            # Если формат даты неверный, используем текущий день
            selected_date = datetime.now()
    else:
        selected_date = datetime.now()

        # Если выбрана дата не сегодня, показываем только этот день (00:00 - 23:00)
    if date_str:
        start_time = selected_date.replace(hour=0, minute=0, second=0, microsecond=0)
        hours = [start_time + timedelta(hours=i) for i in range(24)]
        end_time = start_time + timedelta(hours=24)
    else:
        # По умолчанию — последние 24 часа с текущего момента
        now = datetime.now().replace(minute=0, second=0, microsecond=0)
        hours = [now - timedelta(hours=i) for i in reversed(range(24))]
        start_time = hours[0]
        end_time = hours[-1] + timedelta(hours=1)


    routers = Router.query.all()  # Получаем все роутеры из базы
    devices = Device.query.all()
    start_minute = None
    minutes = []
    start_time_minute = None
    end_time_minute = None
    logs_hour = []

    logs = ScanLog.query.filter(
        ScanLog.scan_datetime >= start_time,
        ScanLog.scan_datetime <= end_time
        ).order_by(ScanLog.scan_datetime).all()
    #print(f'{logs=}')

    # Получаем время:
    hour_str = request.args.get('hour')  # формат: 'YYYY-MM-DD HH:MM:SS'
    if hour_str:
        try:
            selected_hour = datetime.strptime(hour_str, '%Y-%m-%d %H:%M:%S')
            start_minute = selected_hour.replace(minute=0, second=0, microsecond=0)
            minutes = [start_minute + timedelta(minutes=i) for i in range(60)]
            start_time_minute = start_minute
            end_time_minute = start_minute + timedelta(hours=1)

            # Теперь можно безопасно обращаться к start_minute
            logs_hour = ScanLog.query.filter(
                ScanLog.scan_datetime >= start_time_minute,
                ScanLog.scan_datetime <= end_time_minute
            ).order_by(ScanLog.scan_datetime).all()

        except ValueError:
            # Если дата неверна — оставляем всё пустым
            minutes = []
        else:
            # Если параметр hour не передан — оставляем всё пустым
            minutes = []


    # Структура для хранения статусов
    # Для роутеров: status_dict_routers[router_id][ip][hour] = (status, scan_datetime)
    status_dict_routers = defaultdict(lambda: defaultdict(dict))
    # Часовик для роутеров:
    status_dict_routers_hour = defaultdict(lambda: defaultdict(dict))
    #print(f'{status_dict_routers=}')

    # Для устройств: status_dict_devices[device_id][hour] = (status, scan_datetime)
    status_dict_devices = defaultdict(dict)
    # Часовик для устройств:
    status_dict_devices_hour = defaultdict(dict)

    for log in logs: # получаем логи за сутки
        # Округляем время до часа
        log_hour = log.scan_datetime.replace(minute=0, second=0, microsecond=0)

        if log.device_id is None:
            # Это запись для роутера
            # router_id и ip присутствуют
            status_dict_routers[log.router_id][log.ip][log_hour] = (log.status, log.scan_datetime, log.lan4err)
        else:
            # Это запись для устройства
            status_dict_devices[log.device_id][log_hour] = (log.status, log.scan_datetime)

    for log in logs_hour: # получаем логи за час
        # Округляем время до минут
        log_minute = log.scan_datetime.replace(second=0, microsecond=0)
        if log.device_id is None:
            # Это запись для роутера
            # router_id и ip присутствуют
            status_dict_routers_hour[log.router_id][log.ip][log_minute] = (log.status, log.scan_datetime, log.lan4err)
        else:
            # Это запись для устройства
            status_dict_devices_hour[log.device_id][log_minute] = (log.status, log.scan_datetime)


    return render_template('index1.html',
                           title='Статусы устройств за выбранный период',
                           menu=menu,
                           routers=routers,
                           devices=devices,
                           hours=hours,
                           minutes=minutes,
                           status_dict_routers=status_dict_routers,
                           status_dict_routers_hour=status_dict_routers_hour,
                           status_dict_devices=status_dict_devices,
                           status_dict_devices_hour=status_dict_devices_hour,
                           selected_date=selected_date.date() if date_str
                           else None
                           )

@app.route('/hourly_data')
def hourly_data():
    hour_str = request.args.get('hour')
    router_id_arg = request.args.get('router_id')

    print("Получен запрос с параметрами:")
    print("hour:", hour_str)
    print("router_id:", router_id_arg)

    if not hour_str:
        return jsonify({"error": "No hour provided"}), 400

    try:
        selected_hour = datetime.strptime(hour_str, '%Y-%m-%d %H:%M:%S')
    except ValueError as ve:
        print("Ошибка парсинга даты:", ve)
        return jsonify({"error": "Invalid date format"}), 400

    start_time = selected_hour
    end_time = selected_hour + timedelta(hours=1)

    try:
        query = db.session.query(
            ScanLog.id,
            ScanLog.scan_datetime,
            ScanLog.router_id,
            ScanLog.device_id,
            ScanLog.ip,
            ScanLog.status,
            ScanLog.lan4err,
            Router.name.label('router_name'),
            Device.name.label('device_name')
        ).outerjoin(Router, ScanLog.router_id == Router.id) \
         .outerjoin(Device, ScanLog.device_id == Device.id) \
         .filter(
            ScanLog.scan_datetime >= start_time,
            ScanLog.scan_datetime < end_time
        )

        if router_id_arg:
            query = query.filter(ScanLog.router_id == int(router_id_arg))

        logs = query.all()

        result = []
        for row in logs:
            result.append({
                'scan_datetime': row.scan_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                'router_id': row.router_id,
                'router_name': row.router_name or f'Router #{row.router_id}',
                'device_id': row.device_id,
                'device_name': row.device_name or (f'Device #{row.device_id}' if row.device_id else None),
                'ip': row.ip,
                'status': row.status,
                'lan4err': row.lan4err
            })

        return jsonify(result)

    except Exception as e:
        print("Ошибка при выполнении запроса:", str(e))
        return jsonify({"error": "Server error", "details": str(e)}), 500


@app.route('/update_data', methods=['POST'])
def update_data():
    result = subprocess.run([python_executable, scan_lan], capture_output=True, text=True)
    #print('Output:', result.stdout)
    #print('Errors:', result.stderr)
    time.sleep(2)
    return redirect(url_for('index'))  # после обработки обновляем страницу

@app.route('/logs')
def logs():
    try:
        size_bytes = os.path.getsize(monitor_log)
        size_str = format_size(size_bytes)
        # Считаем количество строк в файле

        with open(monitor_log, 'r', encoding='utf-8', errors="ignore") as f:
            lines = f.readlines()

        # Показываем последние 500 строк
        last_lines = lines[-500:]
        line_count = len(lines)

        return render_template('logs.html',
                                title="Просмотр логов (последние 500 строк)  ",
                                menu = menu,
                                line_count= line_count,
                                size_str= size_str,
                                last_lines= last_lines
                               )
    except OSError as e:
        return f"Ошибка при чтении лога: {e}", 500


@app.route('/tools')
def tools():
    print(url_for('tools'))
    return render_template('tools.html', title="Инструменты  ", menu = menu)

@app.route('/contact', methods=['POST', 'GET'])
def contact():
    if request.method == 'POST':
        print(request.form['username'])
        if len(request.form['username']) > 2:
            flash('Сообщение отправлено', category='success')
        else:
            flash('Ошибка отправки', category='error')

    print(url_for('contact'))
    return render_template('contact.html', title="Обратная связь ", menu = menu)


@app.errorhandler(404)
def pageNotFount(errof):
    return render_template('page404.html', title='Страница не найдена', menu=menu)


# Ниже задания для планировщика.
# Очистка логов и запуск сканера каждые 5 мин
# Нужно запланировать:
# - очистку логов flask_log
# - очистку таблицы scan_log раз в год
def scheduled_clean_logs():
    try:
        clean_log_file(monitor_log, days_to_keep=45)
        clean_log_file(flask_log, days_to_keep=45)
    except Exception as e:
        scheduler_logger.error(f"Ошибка очистки логов: {str(e)}")



def run_scan_script():
    # Запускает scan_to_db.py как отдельный процесс
    try:
        result = subprocess.run(
            [python_executable, scan_to_db],
            check=True,
            capture_output=True,
            text=True
        )
        scheduler_logger.info("Scan output:  %s", result.stdout)
    except subprocess.CalledProcessError as e:
        scheduler_logger.info("Scan error:  %s", e.stderr)

def start_scheduler():
    scheduler.init_app(app)
    scheduler.start()
    # Очищать логи 1 числа каждого месяца в 00:30
    scheduler.add_job(
        id='clean_logs_monthly',
        func=scheduled_clean_logs,
        trigger='cron',
        day=1,
        hour=0,
        minute=30
    )
    # Запускать скрипт каждые 5 минут
    scheduler.add_job(
        id='scan_to_db_every_5_minutes',
        func=run_scan_script,
        trigger='interval',
        minutes=5
    )


if __name__ == '__main__':
    if not scheduler.running:
        start_scheduler() # Явный вызов инициализации
    app.run(host='0.0.0.0', port=5002)
