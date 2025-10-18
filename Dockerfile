FROM php:8.2-apache
RUN docker-php-ext-install pdo pdo_mysql pdo_pgsql
COPY . /var/www/html/
