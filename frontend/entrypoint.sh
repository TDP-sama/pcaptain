#!/bin/sh
export NGINX_PORT="${NGINX_PORT:-80}"
# Where nginx forwards /api/ to: the backend service on the compose network.
export BACKEND_UPSTREAM="${BACKEND_UPSTREAM:-backend:7000}"
# Base URL the browser uses for API calls. Default: same server, /api/.
# Set BE_PUBLIC_URL only if the UI must call a backend somewhere else.
export BE_PUBLIC_URL="${BE_PUBLIC_URL:-/api/}"

envsubst '$BE_PUBLIC_URL' < /usr/share/nginx/html/config.template.js > /usr/share/nginx/html/config.js

envsubst '$NGINX_PORT $BACKEND_UPSTREAM' < /etc/nginx/conf.d/default.conf.template > /etc/nginx/conf.d/default.conf

#Start NGINX
exec "$@"
