Утилита сканирующая VPN сеть организации, а именно, подключенные роутеры и важные устройства за ним. 
Принцип работы: Пингуются vpn-IP роутеров, проверяется доступность DNS имени если имеется, пингуется внутренний IP роутера. Если пинги прошли успешно, запускается сканирование устройств за роутером, в зависимости от класса устройства проверка проходит через открытие порта или пингом. Результаты записываются в БД (sqlite). По результатам сканирования формируются письма оповещения в случае, если роутер или устройство пропало со связи, или наоборот появилась связь. Роутеры могут быть стационарные и мобильные, по стационарным роутерам письма оповещения отправляются сразу после сканирования, по мобильным роутерам формируется общая статистика за сутки и письмо отправляется в 7 утра. Сканирование запускается каждые 5 минут. Результаты сканирования выводятся на html страницу. 
БД. Используется sqlite, в базе данных три таблицы: “routers” – информация по роутерам, “devices” – информация по устройствам, “scan_logs” – с результатами сканирования.  Для организации VPN подразумевается использование протоколов L2TP/IPsec и SSTP (но это не важно), под vpn-IP выделены два поля ip1 и ip2 соответственно. В поле ip3 хранится ip адрес внутренний сети, в поле dns доменное имя роутера. В поля lan1, lan2, lan3, lan4 записываются последние статусы по ip1, ip2, ip3, vpn соответственно, могут принимать значения 0 – не в сети, 1 – в сети, 2 – не сканировался. Нужны для формирования таблицы scan_logs. В случае если lan4 принимает значение 0, в поле lan4err записывается цифровой код ошибки. На запущенном сервере, на главной странице с результатами эти коды отображаются в строке с dns. На странице «Инструменты» можно посмотреть расшифровку кодов. 
Веб сервер. Используется Flask. Доступен на порту 5002. Исполняемый файл flask_db.py, в нем свой планировщик: запуск сканирования каждые 5 мин., запуск чистки логов (требует доработки) 1 числа каждого месяца, очищаются записи старше 45 дней, запуск чистки БД (пока не реализовал) 1 числа каждого года, очищается журнал сканирования старше 1,5 года. 
Подготовка к работе: 
1.	Подготовка папки. Создать папку, например по пути /var/www/scan_vpn, команда sudo mkdir -p /var/www/scan_vpn
2.	Меняем права на папку sudo chown -R $USER:$USER /var/www/scan_vpn
3.	Копируем файлы проекта в папку любым способом (если с помощью git, то нужно:
  a.	Установить git
  b.	Создать ssh ключ 
  c.	cd /var/www
  d.	git clone git@github.com:setum77/scan_vpn.git scan_vpn
4.	Подготовить БД.
  a.	Создать копию  routers_bckp.db, затем копию переименовать в routers.db
  b.	Открыть routers.db для редактирования, например в DB Browser for SQLite.
  c.	Заполнить таблицы routers и devices
5.	Подготовить файл .env с параметрами эл. почты:
  a.	Создать копию файла .env_bckp, копию переименовать в .env
  b.	Открыть .env, и внести свои данные: почта отправителя, пароль для SMTP сервера, почта получателя, почта для копии письма.
6.	Установить Python, если не установлен, если установлен проверить версию - нужно не ниже 3.9.19
7.	Установить виртуальное окружение venv:
  a.	python3 -m venv myenv
  b.	активировать его (source myenv/bin/activate)
8.	Установить дополнительные модули (pip install requirements.txt)
9. Добавить права на исполнение на все файлы *.py и *.sh (chmod +x ...)
9.	Настроить планировщик (cron) на запуск Веб сервера. 
  a.	Допустим папка с проектом в /var/www/scan_vpn
  b.	Папка с venv - /var/www/scan_vpn/myenv  если нет, то открываем run_flask_db.sh и редактируем пути
  c.	В планировщик настраиваем задание на запуск при включении команды /var/www/scan_vpn/run_flask_db.sh
  d.	Страница будет доступна по ip адресу на порту 5002. Например http://192.168.0.157:5002/
