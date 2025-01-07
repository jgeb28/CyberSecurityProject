FROM nginx:stable-alpine
COPY Nginx/nginx.conf /etc/nginx/

RUN mkdir -p /etc/nginx/ssl
COPY Nginx/nginx-selfsigned.crt /etc/nginx/ssl
COPY Nginx/nginx-selfsigned.key /etc/nginx/ssl
