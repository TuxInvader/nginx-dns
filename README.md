# NGINX DNS -- GLB/DoH Example Configuration
These files allow you to setup NGINX to perform either DNS over HTTPS (DoH) and/or DNS based GSLB

## DNS over HTTPS (DoH) Gateway
Use the nginx-doh.conf file to run a DoH gateway.
Copy the njs.d and ssl folders into /etc/nginx/ and the nginx-doh.conf to /etc/nginx/nginx.conf

NGINX can act as a DNS(TCP) <-> DNS over TLS (DoT) gateway without any NJS functions. Eg:

```
  upstream dns {
    zone dns 64k;
    server 8.8.8.8:53;
  }

  upstream dot {
    zone dot 64k;
    server 8.8.8.8:853;
  }

  server {
    listen 53;
    listen 853 ssl;
    ssl_certificate /etc/nginx/ssl/certs/doh.local.pem;
    ssl_certificate_key /etc/nginx/ssl/private/doh.local.pem;
    proxy_ssl on;
    proxy_pass dot;
  }
```

NJS is required if you want to act as a gateway between DoH and DNS/DoT. In this case we need the NJS, and the
full configuration in nginx-glb.conf. 

We have a HTTP/2 service listening for requests to /dns-query. We then proxy to a stream service internally which
uses js_filter to pull out the DNS packet from the HTTP wrapper, and forward onto DNS-TCP or a DoT server. The result
is then wrapped back up in a HTTP/1.0 response and passed to the HTTP/2 service for delivery to the client.

NGINX can log as much or as little as you like, and the NJS allows you to process information in the DNS requests and
responses.

## NGINX GSLB (work-in-progress)
Use the nginx-glb.conf file to run an GSLB service.
Copy the njs.d folder into /etc/nginx/ and the nginx-glb.conf to /etc/nginx/nginx.conf

TODO - Describe the example configuration and how to customise it.

