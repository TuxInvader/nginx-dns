## DNS over HTTPS (DoH) Gateway
Use the nginx-doh.conf file to run a DoH gateway.
Copy the njs.d and ssl folders into /etc/nginx/ and the nginx-doh.conf to /etc/nginx/nginx.conf

### Simple DNS(TCP) and DNS over TLS (DoT)
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

### DNS over HTTPS (DoH)
NJS is required if you want to act as a gateway between DoH and DNS/DoT. In this case we need some NJS code, and the
full configuration in nginx-glb.conf.

The full configuration has a HTTP/2 service listening for requests, and does a proxy_pass for requests to /dns-query.
We proxy to an internal stream service on port 8053, which uses js_filter to pull out the DNS packet from the HTTP wrapper,
and forward onto an upstream DNS(TCP) or DoT server.
The result is then wrapped back up in a HTTP response and passed to the HTTP/2 service for delivery to the client.

#### NGINX Stream Server for back-end
Lets look at the stream service first:
```
  server {
    listen 127.0.0.1:8053;
    js_filter doh_filter_request;
    proxy_ssl on;
    proxy_pass dot;
  }
```
We listen on the loopback interface on port 8053. HTTP/1.0 requests will be passed to us from the NGINX http service. The `js_filter`
will find the DNS packet encoded in the request, and forward it on to the upstream DoT service. 

#### NGINX HTTP/2 service for the front-end
Traffic arrives at the stream service via a HTTP/2 server:
```
  upstream dohloop {
    zone dohloop 64k;
    server 127.0.0.1:8053;
  }

  proxy_cache_path /var/cache/nginx/doh_cache levels=1:2 keys_zone=doh_cache:10m;
  server {

    listen 443 ssl http2;
    ssl_certificate /etc/nginx/ssl/certs/doh.local.pem;
    ssl_certificate_key /etc/nginx/ssl/private/doh.local.pem;

    proxy_cache_methods GET POST;

    location / {
      return 404 "404 Not Found\n";
    }

    location /dns-query {
      proxy_http_version 1.0;
      proxy_cache doh_cache;
      proxy_cache_key $scheme$proxy_host$uri$is_args$args$request_body;
      proxy_pass http://dohloop;
    }

  }
```
We listen on the standard HTTPS port for incoming http requests. We return a 404 response to all requests except for those which match our
`/dns-query` location. All dns-queries are forwarded onto the stream service as HTTP/1.0 requests.

#### NGINX Processing Options
The NJS code can perform varying degress of processing on the DNS packets. The fastest for DNS is to do no processing (level 0), but enabling some
processing (level 2) allows NGINX to gather the necessary intelligence (Resource Record TTLs) to enable a HTTP Content-Cache for the DoH requests.
At levels less than 2, we will cache responses, but for just 10 seconds.

Change this setting in the `njs.d/dns/doh.js` file
```
/**
 * DNS Decode Level
 * 0: No decoding, minimal processing required to strip packet from HTTP wrapper (fastest)
 * 1: Parse DNS Header and Question. We can log the Question, Class, Type, and Result Code
 * 2: As 1, but also parse answers. We can log the answers, and also cache responses according to TTL.
 * 3: Very Verbose, log everything as above, but also write packet data to error log (slowest)
**/
var $dns_decode_level = 0;
```

