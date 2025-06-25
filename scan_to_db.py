import logging
import os
import platform
import socket
import subprocess
import smtplib
import datetime
import requests
import threading
from requests.exceptions import RequestException
from sqlalchemy.exc import SQLAlchemyError
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
#from your_app import app
from datetime import datetime, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

work_dir = os.path.dirname(os.path.abspath(__file__))
monitorlog = os.path.join(work_dir, 'monitor2.log') # Файл для логов
lines_ = [] # Список для будущей сборки текста письма
lines_m = [] # Список строк для будущей сборки текста письма по мобильным роутерам
f_lines_m = os.path.join(work_dir, 'lines_m.txt') # Файл для записи статусов Пробоксов и последующей отправки 1 раз в день
db_path = os.path.join(work_dir, 'routers.db')
log_entries = [] # глобальный список для записи статусов ScanLog
log_lock = threading.Lock() # для проверки доступности записи в log_entries

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}?check_same_thread=False'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {'timeout': 30}  # Таймаут в секундах
}

db = SQLAlchemy(app)
db_write_lock = threading.Lock()  # Синхронизация потоков при помощи блокировок

logging.basicConfig(
    filename= monitorlog,
    encoding='UTF-8',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)

def logging_print(text):
    logging.info(text)
    print(text)

load_dotenv()  # загружает переменные из .env

TO_EMAIL = os.getenv("TO_EMAIL")
CC_EMAIL = os.getenv("CC_EMAIL")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")


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

    def ping(self, ip):
        logging_print(f'Ping. Router: {self.name} IP {ip}')
        param = ["-n", "4", "-w", "5500", "-l", "100"] \
            if platform.system().lower() == 'windows' \
            else["-c", "4", "-W", "5", "-s", "100"]
        try:
            output = subprocess.check_output(
                ["ping"] + param + [str(ip)],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            logging_print(f'Ping. Ok. {self.name} IP {ip}')
            return True
        except subprocess.CalledProcessError:
            logging_print(f'Ping. Fail. {self.name} IP {ip}')
            return False

    def check_dns_availability(self, lines=None, lines_mobil=None):
        with app.app_context():
            url = self.dns
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    logging_print(f'    {self.name} DNS available')
                    self.lan4err = None
                    self.check_lan(self.dns, lines, lines_mobil, 'on')
                else:
                    logging_print(f'    {self.name} DNS access fail (status code: {response.status_code})')
                    self.lan4err = response.status_code
                    self.check_lan(self.dns, lines, lines_mobil, 'off')

            except requests.exceptions.ConnectionError as e:
                logging_print(f'    {self.name} DNS connection error: {str(e)}')
                self.lan4err = -1
                self.check_lan(self.dns, lines, lines_mobil, 'off')

            except requests.exceptions.Timeout as e:
                logging_print(f'    {self.name} DNS timeout: {str(e)}')
                self.lan4err = -2
                self.check_lan(self.dns, lines, lines_mobil, 'off')

            except requests.exceptions.HTTPError as e:
                logging_print(f'    {self.name} DNS HTTP error: {str(e)}')
                self.lan4err = -4
                self.check_lan(self.dns, lines, lines_mobil, 'off')

            except requests.exceptions.RequestException as e:
                logging_print(f'    {self.name} DNS request failed: {str(e)}')
                self.lan4err = -3
                self.check_lan(self.dns, lines, lines_mobil, 'off')


    def scan_router(self, lines, lines_mobil):
        # - пингуем
        # - если роутер на любом месте доступен, то:
        # - сканируем устройства за роутером
        logging_print(f'        ***** {self.name} start scan. {datetime.now()} ***** ')

        if self.ping(self.ip1):
            logging_print(f'Router: {self.name} answer by IP-1 {self.ip1}')
            self.check_lan(self.ip1, lines, lines_mobil, 'on')
            self.lan2 = 2
            if self.dns:
                logging_print(f'    {self.name} check DNS')
                self.check_dns_availability(lines, lines_mobil)
            self.if_ip3(lines, lines_mobil)
            self.scan_behind(lines, lines_mobil)
            self.scan_pritok(lines, lines_mobil)
        else:
            if self.ip2:
                if self.ping(self.ip2):
                    logging_print(f'Roter: {self.name} answer by IP-2 {self.ip2}')
                    self.check_lan(self.ip2, lines, lines_mobil, 'on')
                    if self.dns:
                        logging_print(f'    {self.name} check DNS')
                        self.check_dns_availability(lines, lines_mobil)
                    self.if_ip3(lines, lines_mobil)
                    self.scan_behind(lines, lines_mobil)
                    self.scan_pritok(lines, lines_mobil)
                else:
                    logging_print(f'    {self.name} not available by any IP')
                    if self.dns:
                        logging_print(f'    {self.name} check DNS')
                        self.check_dns_availability(lines, lines_mobil)
                    self.lan3 = 2
                    self.check_lan(self.ip1, lines, lines_mobil, 'off')
                    self.check_lan(self.ip2, lines, lines_mobil, 'off')
                    self.off_devices()
            else:
                logging_print(f'    {self.name} not available by IP1, IP2 - not')
                if self.dns:
                    logging_print(f'    {self.name} check DNS')
                    self.check_dns_availability(lines, lines_mobil)
                self.check_lan(self.ip1, lines, lines_mobil,'off')
                self.lan3 = 2
                self.off_devices()
        self.log_router_status()


    def scan_behind(self, lines: list, lines_mobil: list):
        for device in list(self.behind_devices):
            logging_print(f'{device.name} ({device.ip}) port scanning {self.name}')
            if device.check_port():
                device.check_lan_device(lines, lines_mobil, self.mobil, 'on')
                device.log_device_status()
            else:
                device.check_lan_device(lines, lines_mobil, self.mobil, 'off')
                device.log_device_status()

    def scan_pritok(self, lines: list, lines_mobil: list):
        for device in list(self.pritok_devices):
            logging_print(f'{device.name} ({device.ip}) ping behind the router: {self.name}')
            if device.ping():
                device.check_lan_device(lines, lines_mobil, self.mobil, 'on')
                device.log_device_status()
            else:
                device.check_lan_device(lines, lines_mobil, self.mobil, 'off')
                device.log_device_status()

    def off_devices(self):
        all_devices = list(self.behind_devices) + list(self.pritok_devices)
        for device in all_devices:
            router_id_value = device.router_id if device.router_id is not None else device.pritok_router_id
            log_entry = ScanLog(
                scan_datetime=datetime.now(),
                router_id=router_id_value,
                device_id=device.id,
                ip=device.ip,
                status=2
            )
            with log_lock:
                log_entries.append(log_entry)



    def if_ip3(self, lines: list, lines_mobil):
        if self.ip3:
            logging_print(f'Router: {self.name}. Scanning local address {self.ip3}')
            if not self.ping(self.ip3):
                self.lan3 = 0
                logging_print(f'    {self.ip3} fail')
                self.check_lan(self.ip3, lines, lines_mobil, 'vpn')
            else:
                logging_print(f'{self.ip3} ok')
                self.lan3 = 1

    def check_lan(self, ip, lines: list, lines_mobil: list, flag='on', ):
        lan_field = None
        if ip == self.ip1:
            lan_field = 'lan1'
        elif ip == self.ip2:
            lan_field = 'lan2'
        elif ip == self.ip3:
            lan_field = 'lan3'
        elif ip == self.dns:
            lan_field = 'lan4'
        current_status = getattr(self, lan_field)
        if flag == 'on':
            if current_status == 0:
                if self.mobil:
                    lines_mobil.append(f'{datetime.now()}.    {self.name} again on the net')
                else:
                    lines.append(f'{datetime.now()}.    {self.name} again on the net')
                logging_print(f'    {self.name} again on the net')
                setattr(self, lan_field, 1)
            elif current_status == 2:
                setattr(self, lan_field, 1)
        elif flag == 'off':
            if current_status == 1:
                if self.mobil:
                    lines_mobil.append(f'{datetime.now()}.        {self.name}. IP:{ip} not on the net')
                else:
                    lines.append(f'{datetime.now()}.        {self.name}. IP:{ip} not on the net')
                logging_print(f'        {self.name} IP: {ip} not on the net')
                setattr(self, lan_field, 0)
            elif current_status == 2:
                setattr(self, lan_field, 0)
        elif flag == 'vpn':
            if self.mobil:
                    lines_mobil.append(f'{datetime.now()}.    Router {self.name}. IP:{ip} offline, internal address is unavailable, check VPN')
            else:
                lines.append(f'{datetime.now()}.    Router {self.name}. IP:{ip} offline, internal address is unavailable, check VPN')
            logging_print(f'    Роутер {self.name}. IP:{ip} offline, internal address is unavailable, check VPN')
            setattr(self, lan_field, 0)


    def log_router_status(self):
        ips_lan = [
            (self.ip1, self.lan1),
            (self.ip2, self.lan2),
            (self.ip3, self.lan3),
            (self.dns, self.lan4),
        ]
        for ip, lan_status in ips_lan:
            if ip is None:
                continue
            if self.lan4err:
                log_entry = ScanLog(
                    scan_datetime=datetime.now(),
                    router_id=self.id,
                    device_id=None,
                    status=lan_status,
                    ip=ip,
                    dns=self.dns,
                    lan4err=self.lan4err,
                )
            else:
                log_entry = ScanLog(
                    scan_datetime=datetime.now(),
                    router_id=self.id,
                    device_id=None,
                    ip=ip,
                    status=lan_status,
                )

            with log_lock:
                log_entries.append(log_entry)




class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String)
    name = db.Column(db.String, nullable=False)
    lan = db.Column(db.Integer)
    router_id = db.Column(db.Integer, db.ForeignKey('routers.id'))
    pritok_router_id = db.Column(db.Integer, db.ForeignKey('routers.id'))

    def check_port(self, timeout=1):
        logging_print(f'Port. Device: {self.name}. Checking connection {self.ip}')
        ports = {
            'HTTP': 80,
            'HTTPS': 443,
            'FTP': 21,
            'SSH': 22,

            'VNC': 5900,
            'KeenAdm': 5080,
        }
        for protocol, port in ports.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((str(self.ip), port))
                    #print(f'{self.name}. {protocol} - {result}')
                    if result == 0:
                        logging_print(f'Port. Ok. {self.name}. port: {protocol}')
                        return True

            except Exception as e:
                # Log the exception if needed, but continue checking other ports
                logging_print(f'Error checking port {port} ({protocol}): {e}')
                # Do NOT return False here; continue checking other ports
        logging_print(f'Port. Fail. {self.name}')
        return False

    def ping(self):
        logging_print(f'Ping. Device: {self.name}. IP {self.ip}')
        param = ["-n", "4", "-w", "5500", "-l", "100"] \
            if platform.system().lower() == 'windows' \
            else["-c", "4", "-W", "5", "-s", "100"]
        try:
            output = subprocess.check_output(
                ["ping"] + param + [str(self.ip)],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            logging_print(f'Ping. Ok. Device: {self.name}')
            return True
        except subprocess.CalledProcessError:
            logging_print(f'Ping. Fail. Device: {self.name}')
            return False


    def log_device_status(self):
        router_id_value = self.router_id if self.router_id is not None else self.pritok_router_id
        log_entry = ScanLog(
            scan_datetime=datetime.now(),
            router_id=router_id_value,
            device_id=self.id,
            ip=self.ip,
            status=self.lan
        )
        with log_lock:
            log_entries.append(log_entry)


    def check_lan_device(self, lines: list, lines_mobil, mobil, flag='on', ):
        if flag == 'on':
            if self.lan == 0:
                if mobil == 1:
                    lines_mobil.append(f'{datetime.now()}.    Device: {self.name} again on the net')
                else:
                    lines.append(f'{datetime.now()}.    Device: {self.name} again on the net')
                logging_print(f'    Device: {self.name} again on the net')
                self.lan = 1
        elif flag == 'off':
            if self.lan == 1:
                if mobil == 1:
                    lines_mobil.append(f'{datetime.now()}. Device: {self.name}. IP:{self.ip} offline')
                else:
                    lines.append(f'{datetime.now()}. Device: {self.name}. IP:{self.ip} offline')
                logging_print(f'    Device: {self.name} IP:{self.ip} offline')
                self.lan = 0

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

# Сборка email и отправка
def send_notification_email(text):
    # Отправка письма заданному адресату
    # Параметры отправителя и SMTP-сервера
    smtp_server = "smtp.mail.ru"
    smtp_port = 465
    sender_email = SENDER_EMAIL
    sender_password = SENDER_PASSWORD
    to_email = TO_EMAIL
    cc_email = CC_EMAIL
    charset = 'Content-Type: text/plain; charset=utf-8'
    mime = 'MIME-Version: 1.0'
    recipients = [to_email, cc_email]

    # Тема письма
    subject = "Отчет по устройствам 'ГПБ'"

    # формируем тело письма
    body = "\r\n".join((f"From: {sender_email}",
                        f"To: {to_email}",
                        f"Cc: {cc_email}",
                        f"Subject: {subject}",
                        mime,
                        charset,
                        "",
                        text))
    try:
        # Настраиваем соединение с SMTP-сервером
        # Порт 465 и starttls — это взаимоисключаемые вещи. Для 465 порта нужно smtplib.SMTP_SSL
        smtp = smtplib.SMTP_SSL(smtp_server, smtp_port)
        #smtp.starttls()  # Защищенное соединение. Нужно для 25 порта
        smtp.ehlo()
        # Логинимся
        smtp.login(sender_email, sender_password)
        smtp.sendmail(sender_email, recipients,  body.encode('UTF-8'))
        logging_print("Письмо отправлено успешно. ")
    except smtplib.SMTPException as err:
        logging_print(f"Ошибка при отправке письма: {err}")
        raise err
    finally:
        smtp.quit()


if __name__ == '__main__':
    with app.app_context():
        # Получаем все роутеры из базы
        routers = Router.query.all()
        # devices = Device.query.all()
        # scan_time = datetime.now()

        # Функция-обёртка для сканирования одного роутера
        def scan_router_wrapper(router):
            with app.app_context():
                try:
                    router.scan_router(lines_, lines_m)

                except Exception as e:
                    logging_print(f"Error in scan_router_wrapper for {router.name}: {e}")

        # Запускаем сканирование в 6 потоков
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(scan_router_wrapper, router) for router in routers]
            for future in as_completed(futures):
                future.result()


            # # Единая транзакция в главном потоке
            try:
                all_devices = []
                for router in routers:
                    all_devices.extend(list(router.behind_devices))
                    all_devices.extend(list(router.pritok_devices))

                db.session.add_all(routers + all_devices + log_entries)
                db.session.flush()
                with db_write_lock:
                    logging_print("Committing changes to database")
                    db.session.commit()
                    logging_print(f"{datetime.now()} Database update successful")
            except SQLAlchemyError as e:
                db.session.rollback()
                logging_print(f"{datetime.now()} Database error during commit: {str(e)}")

        print(f"        Сканирование завершено {datetime.now()}")

        print('\nСтрочки Lines_ ')
        for line in lines_:
            print(line)

        print('\nСтрочки Lines_m ')
        for line in lines_m:
            print(line)

        # Если есть строки для отправки, формируем текст письма и отправляем
        if lines_:
            email_text = (f'Отчет сформирован {datetime.now()}\r\n\r\n  '
                          f'Посмотреть в таблице http://192.168.0.157:5002/index1\r\n\n\n')
            email_text += "\r\n".join(lines_)
            send_notification_email(email_text)

        # Если есть строки для отправки по мобильным роутерам, записываем в файл f_lines_m
        if lines_m:
            with open(f_lines_m, 'a', encoding='utf-8') as f:
                f.write("\r\n".join(lines_m) + "\r\n")

        # Проверяем время, если время с 7 до 8 то отправляем письмо и очищаем файл f_linew_W
        now = datetime.now().time()
        start_time = time(7, 0)  # 8:00
        end_time = time(7, 8)  # 9:00

        if start_time <= now < end_time:
            with open(f_lines_m, 'r', encoding='utf-8') as f:
                email_text = (f'Отчет по машинам {datetime.now()}\r\n\r\n  '
                              f'Посмотреть в таблице http://192.168.0.157:5002/index1\r\n\n\n')
                email_text += "\r\n".join(f.readlines())
                send_notification_email(email_text)
            with open(f_lines_m, 'w', encoding='utf-8') as f:
                f.write("")
