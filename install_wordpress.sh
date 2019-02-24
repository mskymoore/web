#!/bin/bash

WP_DOMAIN="example.com"
WP_ADMIN_USERNAME="admin"
WP_ADMIN_PASSWORD="password"
WP_ADMIN_EMAIL="user@example.com"
WP_DB_NAME="wordpress"
WP_DB_USERNAME="wordpress"
WP_DB_PASSWORD="password"
WP_PATH="/var/www/wordpress"
MYSQL_ROOT_PASSWORD="password"

# setup msql
echo "mysql-server-5.7 mysql-server/root_password password $MYSQL_ROOT_PASSWORD" | sudo debconf-set-selections
echo "mysql-server-5.7 mysql-server/root_password_again password $MYSQL_ROOT_PASSWORD" | sudo debconf-set-selections

# install necessary sw
sudo apt install -y nginx php php-mysql php-curl php-gd mysql-server php7.0-fpm

# setup database
mysql -u root -p$MYSQL_ROOT_PASSWORD <<EOF
CREATE USER '$WP_DB_USERNAME'@'localhost' IDENTIFIED BY '$WP_DB_PASSWORD';
CREATE DATABASE $WP_DB_NAME;
GRANT ALL ON $WP_DB_NAME.* TO '$WP_DB_USERNAME'@'localhost';
EOF

# configure nginx
sudo mkdir -p $WP_PATH/public $WP_PATH/logs
sudo tee /etc/nginx/sites-available/$WP_DOMAIN <<EOF
server {
  listen 80;
  server_name $WP_DOMAIN www.$WP_DOMAIN;

  root $WP_PATH/public;
  index index.php;

  access_log $WP_PATH/logs/access.log;
  error_log $WP_PATH/logs/error.log;

  location / {
    try_files \$uri \$uri/ /index.php?\$args;
  }

  location ~ \.php\$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php7.0-fpm.sock;
  }
}
EOF


sudo ln -s /etc/nginx/sites-available/$WP_DOMAIN /etc/nginx/sites-enabled/$WP_DOMAIN
sudo systemctl restart nginx

# configure ssl
sudo apt-get update
sudo apt-get install -y software-properties-common
sudo add-apt-repository universe
sudo add-apt-repository ppa:certbot/certbot
sudo apt-get update
sudo apt-get install -y certbot python-certbot-apache

sudo mkdir -p $WP_PATH
sudo certbot certonly --agree-tos --webroot --webroot-path /var/www/html -d $WP_DOMAIN -d www.$WP_DOMAIN -m $WP_ADMIN_EMAIL

sudo openssl dhparam -out /etc/letsencrypt/live/$WP_DOMAIN/dhparam.pem 2048

# reconfigure nginx
sudo tee /etc/nginx/sites-available/$WP_DOMAIN <<EOF
server {
  listen 80;
  server_name $WP_DOMAIN www.$WP_DOMAIN;
  return 301 https://\$server_name\$request_uri;
}

server {
  listen 443 ssl http2;
  server_name $WP_DOMAIN www.$WP_DOMAIN;

  root $WP_PATH/public;
  index index.php;

  access_log $WP_PATH/logs/access.log;
  error_log $WP_PATH/logs/error.log;

  ssl_certificate           /etc/letsencrypt/live/$WP_DOMAIN/fullchain.pem;
  ssl_certificate_key       /etc/letsencrypt/live/$WP_DOMAIN/privkey.pem;
  ssl_trusted_certificate   /etc/letsencrypt/live/$WP_DOMAIN/chain.pem;
  ssl_dhparam               /etc/letsencrypt/live/$WP_DOMAIN/dhparam.pem;

  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS';
  ssl_prefer_server_ciphers on;
  ssl_session_timeout 1d;
  ssl_session_cache shared:SSL:50m;
  ssl_session_tickets off;
  ssl_stapling on;
  ssl_stapling_verify on;
  resolver 8.8.4.4 8.8.8.8 valid=300s;
  resolver_timeout 10s;

  add_header Strict-Transport-Security max-age=15552000;

  location / {
    try_files \$uri \$uri/ /index.php?\$args;
  }

  location ~ \.php\$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php7.0-fpm.sock;
  }
}
EOF
sudo systemctl restart nginx

# automate certificate renewal
sudo tee /etc/cron.daily/letsencrypt <<EOF
certbot renew --agree-tos && systemctl restart nginx
EOF
sudo chmod +x /etc/cron.daily/letsencrypt

# setup wordpress dir
sudo rm -rf $WP_PATH/public/ # !!!
sudo mkdir -p $WP_PATH/public/
sudo chown -R $USER $WP_PATH/public/
cd $WP_PATH/public/

# install wordpress
wget https://wordpress.org/latest.tar.gz
tar xf latest.tar.gz --strip-components=1
rm latest.tar.gz

# configure wordpress
mv wp-config-sample.php wp-config.php
sed -i s/database_name_here/$WP_DB_NAME/ wp-config.php
sed -i s/username_here/$WP_DB_USERNAME/ wp-config.php
sed -i s/password_here/$WP_DB_PASSWORD/ wp-config.php
echo "define('FS_METHOD', 'direct');" >> wp-config.php


sudo chown -R www-data:www-data $WP_PATH/public/


curl "http://$WP_DOMAIN/wp-admin/install.php?step=2" \
  --data-urlencode "weblog_title=$WP_DOMAIN"\
  --data-urlencode "user_name=$WP_ADMIN_USERNAME" \
  --data-urlencode "admin_email=$WP_ADMIN_EMAIL" \
  --data-urlencode "admin_password=$WP_ADMIN_PASSWORD" \
  --data-urlencode "admin_password2=$WP_ADMIN_PASSWORD" \
  --data-urlencode "pw_weak=1"

# set custom nonces
sudo apt install pwgen

sed -i "s/define('AUTH_KEY',\s*'4312551792070345346132113');/define('AUTH_KEY', '`pwgen -1 -s 64`');/" wp-config.php
sed -i "s/define('SECURE_AUTH_KEY',\s*'2759870436063744503091845');/define('SECURE_AUTH_KEY', '`pwgen -1 -s 64`');/" wp-config.php
sed -i "s/define('LOGGED_IN_KEY',\s*'9274833957862536705334053');/define('LOGGED_IN_KEY', '`pwgen -1 -s 64`');/" wp-config.php
sed -i "s/define('NONCE_KEY',\s*'0285435948152332628721937');/define('NONCE_KEY', '`pwgen -1 -s 64`');/" wp-config.php
sed -i "s/define('AUTH_SALT',\s*'3181443583998042984805318');/define('AUTH_SALT', '`pwgen -1 -s 64`');/" wp-config.php
sed -i "s/define('SECURE_AUTH_SALT',\s*'8247792442034277321663279');/define('SECURE_AUTH_SALT', '`pwgen -1 -s 64`');/" wp-config.php
sed -i "s/define('LOGGED_IN_SALT',\s*'1853285203515292508444512');/define('LOGGED_IN_SALT', '`pwgen -1 -s 64`');/" wp-config.php
sed -i "s/define('NONCE_SALT',\s*'9457675010713294491210221');/define('NONCE_SALT', '`pwgen -1 -s 64`');/" wp-config.php

# move wp-config out of public directory
sudo mv $WP_PATH/public/wp-config.php $WP_PATH/wp-config.php

# set more restrictive permissions 
sudo chown -R root:root $WP_PATH
sudo chown -R $USER $WP_PATH/public/
sudo chown -R www-data:www-data $WP_PATH/public/wp-content/

# delete some files
sudo rm $WP_PATH/public/readme*

# configure firewall
sudo apt install ufw

sudo ufw default deny incoming
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
echo y | sudo ufw enable

# final setup
sudo systemctl stop apache2
sudo systemctl disable apache2
sudo systemctl restart nginx
sudo systemctl enable nginx
sudo systemctl enable php7.0-fpm
sudo systemctl start php7.0-fpm
