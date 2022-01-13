# NGINX DNS (DNS/DoT/DoH)

This repository contains some NJS code, and example configuration files for using NGINX with DNS services.
NGINX can be used to perform load balancing for DNS (TCP/UDP), and also DNS over TLS (DoT) and DNS over HTTPS (DoH)

NGINX can also be used to provide Global Server Load Balancing (GSLB).

See the example configuration files in the [examples](examples) folder.

## Setup
Copy the njs.d folder into /etc/nginx/ and one of the NGINX DoH [examples](examples) to /etc/nginx/nginx.conf
The ssl folder contains a test certificate, you will likely want to generate and use your own certificate and update the nginx.conf file accordingly.

## Simple DNS
NGINX can do simple DNS load balancing, without the need for NJS, using the standard Stream module directives.
```
stream {

  # DNS upstream pool.
  upstream dns {
    zone dns 64k;
    server 8.8.8.8:53;
  }

  # DNS Server. Listens on both TCP and UDP
  server {
    listen 53;
    listen 53 udp;
    proxy_responses 1;
    proxy_pass dns;
  }
}
```

However if you want to carry out layer 7 inspection of the DNS traffic for logging or routing purposes, then you will need to use the NJS module
included in this repository. 

To perform DNS routing, you need to make a `js_preread` function call in the server context, and use a `js_set` function with a `map`.
For example:
```
stream {
  js_import /etc/nginx/njs.d/dns/dns.js;
  js_set $dns_qname dns.get_qname;

  map $dns_qname $upstream_pool {
    hostnames;
    *.nginx one;
    default two;
  }

  upstream one {
    ...
  }

  upstream two {
    ...
  }

  server {
    listen 53 udp;
    js_preread dns.preread_dns_request;
    proxy_responses 1;
    proxy_pass $upstream_pool;
  }

}
```

## DNS over TLS (DoT) and DNS over HTTPS (DoH) Gateway

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
The above example will accpet DNS and DoT requests, and forward them to a DoT upstream. If your upstream is DNS, and you want to terminate DoT on NGINX, then remove the `proxy_ssl on;` directive, and change the `proxy_pass` directive to use the standard DNS upstream.

NJS is required if you want to act as a gateway between DoH and DNS/DoT.
See the example configuration files in the [examples](examples) folder.

The full configuration has a HTTP/2 service listening for requests, and does a proxy_pass for requests to /dns-query. 
We proxy to an internal stream service on port 8053, which uses js_filter to pull out the DNS packet from the HTTP wrapper,
and forward onto an upstream DNS(TCP) or DoT server.
The result is then wrapped back up in a HTTP response and passed to the HTTP/2 service for delivery to the client.

NGINX can log as much or as little as you like, and the NJS allows you to process information in the DNS requests and
responses.

See: [docs/nginx-dns-over-https](docs/nginx-dns-over-https.md) for more information

## NGINX GSLB (work-in-progress)
Use the nginx-glb.conf file to run an GSLB service.
Copy the njs.d folder into /etc/nginx/ and the nginx-glb.conf to /etc/nginx/nginx.conf

TODO - Describe the example configuration and how to customise it.

