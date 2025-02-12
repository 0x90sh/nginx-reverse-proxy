FROM ubuntu:22.04

ENV TZ=Europe/Zurich
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    software-properties-common && \
    add-apt-repository -y ppa:ondrej/php && \
    apt-get update && \
    apt-get install -y \
    nginx \
    curl \
    git \
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
    php8.2-gd \
    libpcre3-dev \
    build-essential \
    lua5.3 \
    liblua5.3-dev \
    luarocks \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://openresty.org/package/pubkey.gpg | apt-key add - && \
    add-apt-repository -y "deb http://openresty.org/package/ubuntu $(lsb_release -sc) main" && \
    apt-get update && \
    apt-get install -y openresty

RUN luarocks install lua-resty-redis
RUN luarocks install lua-cjson
RUN luarocks install lua-resty-http
RUN luarocks install lua-resty-rsa
RUN luarocks install lua-resty-openssl
RUN luarocks install lua-resty-shell
RUN luarocks install lua-resty-iputils

RUN adduser --system --no-create-home --disabled-login --group nginx

RUN chown -R nginx:nginx /usr/local/openresty/lualib/resty \
    && chmod -R 755 /usr/local/openresty/lualib/resty

RUN rm /usr/local/openresty/nginx/conf/nginx.conf

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

RUN mkdir -p /var/www/html /var/www/preprocess /var/www/hosts && \
    chown -R nginx:nginx /var/www/html /var/www/preprocess /var/www/hosts && \
    chmod -R 755 /var/www/html /var/www/preprocess /var/www/hosts && \
    mkdir -p /nginx_cache/

RUN sed -i 's!^listen = .*!listen = 127.0.0.1:9000!' /etc/php/8.2/fpm/pool.d/www.conf

COPY lua /var/www/preprocess
COPY hosts.json /var/www/hosts/hosts.json

EXPOSE 80

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]