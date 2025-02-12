#!/bin/bash

service php8.2-fpm start
/usr/local/openresty/bin/openresty -c /usr/local/openresty/nginx/conf/nginx.conf -g 'daemon off;'
