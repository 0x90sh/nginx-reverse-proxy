FROM ubuntu:22.04

ENV TZ=Europe/Zurich
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    software-properties-common && \
    add-apt-repository -y ppa:ondrej/php && \
    apt-get update && \
    apt-get install -y \
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
      luarocks && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://openresty.org/package/pubkey.gpg | apt-key add - && \
    add-apt-repository -y "deb http://openresty.org/package/ubuntu $(lsb_release -sc) main" && \
    apt-get update && \
    apt-get install -y openresty

RUN mkdir -p /root/.luarocks && \
    chmod -R 755 /root/.luarocks

RUN luarocks config --local variables.LUA_DIR /usr/local/openresty/luajit && \
    luarocks config --local variables.LUA_INCDIR /usr/local/openresty/luajit/include/luajit-2.1 && \
    luarocks config --local variables.LUA_LIBDIR /usr/local/openresty/luajit/lib
    
RUN sudo luarocks install luafilesystem --lua-version=5.1


RUN luarocks install lua-resty-redis && \
    #luarocks install lua-cjson && \
    luarocks install lua-resty-http && \
    luarocks install lua-resty-rsa && \
    luarocks install lua-resty-openssl && \
    luarocks install lua-resty-shell && \
    luarocks install lua-resty-iputils

RUN adduser --system --no-create-home --disabled-login --group nginx

RUN chown -R nginx:nginx /usr/local/openresty/lualib/resty && \
    chmod -R 755 /usr/local/openresty/lualib/resty

RUN rm /usr/local/openresty/nginx/conf/nginx.conf

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

RUN mkdir -p /var/log/nginx && chown nginx:nginx /var/log/nginx

RUN mkdir -p /var/www/html /var/www/preprocess /var/www/hosts && \
    chown -R nginx:nginx /var/www/html /var/www/preprocess /var/www/hosts && \
    chmod -R 755 /var/www/html /var/www/preprocess /var/www/hosts && \
    mkdir -p /nginx_cache/ && \
    mkdir -p /etc/resty-auto-ssl && \
    chown -R nginx:nginx /etc/resty-auto-ssl && \
    chmod -R 755 /etc/resty-auto-ssl
    
RUN sed -i 's!^listen = .*!listen = 127.0.0.1:9000!' /etc/php/8.2/fpm/pool.d/www.conf

COPY lua /var/www/preprocess
COPY hosts.json /var/www/hosts/hosts.json
COPY error_html /usr/share/nginx/html

EXPOSE 80
EXPOSE 443

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
