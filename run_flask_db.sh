#!/bin/bash
cd /var/www/
source /var/www/scan_vpn/myenv/bin/activate
exec python -m scan_vpn.flask_db
