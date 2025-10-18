FROM php:8.2-apache

# Install PostgreSQL dependencies
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql pdo_mysql

# Enable Apache mod_rewrite
RUN a2enmod rewrite

COPY . /var/www/html/
