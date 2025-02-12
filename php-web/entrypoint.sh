
#!/bin/bash

echo "Starting PHP-FPM..."
service php8.2-fpm start || {
    echo "Failed to start PHP-FPM."
    exit 1
}

nginx -g 'daemon off;'
