import platform
import socket
import ipaddress
import subprocess


def check_ports(ip, port1, port2, timeout=1):
    for port in range(port1, port2): # 1, 65536

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((str(ip), port))
                # print(f'{self.name}. {protocol} - {result}')
                if result == 0:
                    print(f'\n\n {ip} ответило на порт {port}')
                else:
                    if port % 100 == 0:
                        print(f'{port}; ', end='')


        except Exception:
            return False
    print(f' {ip} скан портов не прошло')
    return False

def standart_port(ip, timeout=1):
    ports = {
        'HTTP': 80,
        'HTTPS': 443,
        'FTP': 21,
        'SSH': 22,

        'VNC': 5900,
        'KeenAdm': 5080,
    }
    # reserv_port = {'UPnP': 1900,}

    for protocol, port in ports.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((str(ip), port))
                #print(f'{self.name}. {protocol} - {result}')
                if result == 0:
                    return print(f' {ip} ответило на порт {protocol}')

        except Exception as e:
            # Log the exception if needed, but continue checking other ports
            return print(f'Error checking port {port} ({protocol}): {e}')
            # Do NOT return False here; continue checking other ports
    return print(f' {ip} скан портов не прошло')

def ping(ip):
    param = ["-n", "4", "-w", "5500", "-l", "100"] \
        if platform.system().lower() == 'windows' \
        else["-c", "4", "-W", "5", "-s", "100"]
    try:
        output = subprocess.check_output(
            ["ping"] + param + [str(ip)],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        print(f'{ip} - успешно отпинговался')
        return True
    except subprocess.CalledProcessError:
        print(f'{ip} - не отпинговался')
        return False

id_scan = int(input('''Сканировать стандратные порты - 1; 
указать диапазон - 2; 
пинговать - 3 
>> '''))
device = ipaddress.ip_address(input('Введите ip: '))
if id_scan == 1:
    standart_port(device)
elif id_scan == 2:
    port_s = int(input('Введите начальный порт: '))
    port_e = int(input('Введите конечный порт: '))
    check_ports(device, port_s, port_e)
elif id_scan == 3:
    ping(device)




