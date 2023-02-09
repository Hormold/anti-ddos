# Automatic managmant of Cloudflare's firewall rules (rate limits)

System automatically manages Cloudflare's firewall rules (rate limits) to prevent DDoS attacks. 

## /etc/nginx/nginx.conf modifications

It nessesary to add the following lines to the `http` section of the `/etc/nginx/nginx.conf` file:
```
	log_format vhost '$remote_addr - $remote_user [$time_local] '
                '"$request" $status $body_bytes_sent '
                '"$http_host" "$http_user_agent"';
    access_log /var/log/nginx/access.log vhost;
```

This modification is required to make the system work properly, because it uses the `access.log` file to detect DDoS attacks.