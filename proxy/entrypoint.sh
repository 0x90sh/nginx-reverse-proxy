#!/bin/bash

service php8.2-fpm start
/usr/local/openresty/bin/openresty -g 'daemon off;'