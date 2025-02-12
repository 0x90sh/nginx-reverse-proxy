FROM ubuntu:22.04
ENV TZ=Europe/Zurich

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    software-properties-common && \
    add-apt-repository ppa:ondrej/php && \
    apt-get update && \
    apt-get install -y \
    nginx \
    curl \
    php8.2-fpm \
    php8.2-mysql \
    php8.2-curl \
    php8.2-mbstring \
    php8.2-cli \
    php8.2-common \
    php8.2-opcache \
    php8.2-readline \
    php8.2-xml \
    php8.2-zip \
    && rm -rf /var/lib/apt/lists/*

RUN sed -i "s/^;date.timezone =.*/date.timezone = Europe\/Zurich/" /etc/php/8.2/fpm/php.ini && \
    sed -i "s/^;date.timezone =.*/date.timezone = Europe\/Zurich/" /etc/php/8.2/cli/php.ini

RUN adduser --system --no-create-home --disabled-login --group nginx

RUN rm /etc/nginx/sites-available/default

COPY nginx.conf /etc/nginx/nginx.conf
RUN chown nginx:nginx /etc/nginx/nginx.conf

RUN mkdir -p /var/www/html && \
    chown -R nginx:nginx /var/www/html && \
    chmod -R 755 /var/www/html

WORKDIR /var/www/html

RUN chown -R nginx:nginx /var/www/html && \
    chmod -R 755 /var/www/html

RUN sed -i 's!^listen = .*!listen = 127.0.0.1:9000!' /etc/php/8.2/fpm/pool.d/www.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]