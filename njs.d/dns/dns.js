import dns from "libdns.js";
export default {get_qname, get_response, preread_doh_request, preread_dns_request, filter_doh_request};

/**
 * DNS Decode Level
 * 0: No decoding, minimal processing required to strip packet from HTTP wrapper (fastest)
 * 1: Parse DNS Header and Question. We can log the Question, Class, Type, and Result Code
 * 2: As 1, but also parse answers. We can log the answers, and also cache responses in HTTP Content-Cache
 * 3: Very Verbose, log everything as above, but also write packet data to error log (slowest)
**/
var dns_decode_level = 3;

/**
 * DNS Question Load Balancing
 * Set this to true, if you want to pick the upstream pool based on the DNS Question.
 * Doing so will disable HTTP KeepAlives for DoH so that we can create a new socket for each query
**/
var dns_question_balancing = false;

// The DNS Question name
var dns_name = String.bytesFrom([]);

function get_qname(s) {
  return dns_name;
}

// The Optional DNS response, this is set when we want to block a specific domain
var dns_response = String.bytesFrom([]);

function get_response(s) {
  return dns_response.toString();
}

// Encode the given number to two bytes (16 bit)
function to_bytes( number ) {
  return String.fromCodePoint( ((number>>8) & 0xff), (number & 0xff) ).toBytes();
}

function debug(s, msg) {
  if ( dns_decode_level >= 3 ) {
    s.warn(msg);
  }
}

// Get value from queryString
function getQueryVar(query, key) {
  var vars = query.split('&');
  for (var i = 0; i < vars.length; i++) {
    var pair = vars[i].split('=');
    if (pair.length < 2) {
      return '';
    }
    if (decodeURIComponent(pair[0]) == key) {
      return decodeURIComponent(pair[1]);
    }
  }
  return '';
}

function process_doh_request(s, decode, scrub) {
  s.on("upload", function(data,flags) {
    if ( data.length == 0 ) {
      return;
    }
    data.split("\r\n").forEach( function(line) {
      var bytes;
      var packet;

      if ( line.toString('hex').startsWith('0000') ) {
        bytes = line;
      } else if ( line.toString().startsWith("GET /dns-query?") ) {
        bytes = String.bytesFrom(getQueryVar(line.toString().slice("GET /dns-query?".length, line.length - " HTTP/1.1".length), 'dns'), 'base64url');
      }

      if (bytes) {
        debug(s, "process_doh_request: DNS Req: " + bytes.toString('hex') );
        if (decode) {
          packet = dns.parse_packet(bytes);
          debug(s, "process_doh_request: DNS Req ID: " + packet.id );
          dns.parse_question(packet);
          debug(s,"process_doh_request: DNS Req Name: " + packet.question.name);
          dns_name = packet.question.name;
        }
        if (scrub) {
          domain_scrub(s, bytes, packet);
          s.done();
        } else {
          s.send( to_bytes(bytes.length) );
          s.send( bytes, {flush: true} );
        }
      } else {
        if ( ! scrub) {
          debug(s, "process_doh_request: DNS Req: " + line.toString() );
          s.send("");
          data = "";
        }
      }
    });
  });
}

function process_dns_request(s, decode, scrub) {
   s.on("upload", function(bytes,flags) {
    if ( bytes.length == 0 ) {
      return;
    }
    var packet;
    if (bytes) {
      if (s.variables.protocol == "TCP") {
        // Drop the TCP length field
        bytes = bytes.slice(2);
      }
      debug(s, "process_dns_request: DNS Req: " + bytes.toString('hex') );
      if (decode) {
        packet = dns.parse_packet(bytes);
        debug(s, "process_dns_request: DNS Req ID: " + packet.id );
        dns.parse_question(packet);
        debug(s,"process_dns_request: DNS Req Name: " + packet.question.name);
        dns_name = packet.question.name;
      }
      if (scrub) {
        domain_scrub(s, bytes, packet);
        s.done();
      } else {
        if (s.variables.protocol == "TCP") {
          s.send( to_bytes(bytes.length) );
        }
        s.send( bytes, {flush: true} );
      }
    }
  });
}

function domain_scrub(s, data, packet) {
  var found = false;
  if ( s.variables.server_port == 9953 ) {
    dns_response = dns.shortcut_nxdomain(data, packet);
    if (s.variables.protocol == "TCP" ) {
      dns_response = to_bytes( dns_response.length ) + dns_response;
    }
    debug(s,"Scrubbed: Response: " + dns_response.toString('hex') );
  } else if ( s.variables.server_port == 9853 ) {
    var answers = [];
    if ( packet.question.type == dns.dns_type.A ) {
      answers.push( {name: packet.question.name, type: dns.dns_type.A, class: dns.dns_class.IN, ttl: 300, rdata: "0.0.0.0" } );
    } else if ( packet.question.type == dns.dns_type.AAAA ) {
      answers.push( {name: packet.question.name, type: dns.dns_type.AAAA, class: dns.dns_class.IN, ttl: 300, rdata: "0000:0000:0000:0000:0000:0000:0000:0000" } );
    }
    dns_response = dns.shortcut_response(data, packet, answers);
    if (s.variables.protocol == "TCP" ) {
      dns_response = to_bytes( dns_response.length ) + dns_response;
    }
    debug(s,"Scrubbed: Response: " + dns_response.toString('hex') );
  } else { 
    debug(s,"Scrubbing: Check: Name: " + packet.question.name );
    if ( s.variables.scrub_action ) {
      debug(s, "Scrubbing: Check: EXACT MATCH: Name: " + packet.question.name + ", Action: " + s.variables.scrub_action );
      dns_response = s.variables.scrub_action;
      return;
    } else {
      ["blocked", "blackhole"].forEach( function( list ) {
        if(found) { return };
        var blocked = s.variables[ list + "_domains" ];
        if ( blocked ) {
          blocked = blocked.split(',');
          blocked.forEach( function( domain ) {
            if (packet.question.name.endsWith( domain )) {
              debug(s,"Scrubbing: Check: LISTED: Name: " + packet.question.name + ", Action: " + list );
              dns_response = list;
              found = true;
              return;
            }
          });
        }
      });
      if(found) { return };
    }
    debug(s,"Scrubbing: Check: NOT FOUND: Name: " + packet.question.name);
  }
}

function preread_dns_request(s) {
  process_dns_request(s, true, true);
}

function preread_doh_request(s) {
  process_doh_request(s, true, true);
}

function filter_doh_request(s) {

  if ( dns_decode_level >= 3 ) {
    process_doh_request(s, true, false);
  } else {
    process_doh_request(s, false, false);
  }

  s.on("download", function(data, flags) {
    if ( data.length == 0 ) {
      return;
    }
    // Drop the TCP length field
    data = data.slice(2);

    debug(s, "DNS Res: " + data.toString('hex') );
    var packet;
    var answers = "";
    var cache_time = 10;
    if ( dns_question_balancing ) {
      s.send("HTTP/1.1 200\r\nConnection: Close\r\nContent-Type: application/dns-message\r\nContent-Length:" + data.length + "\r\n");
    } else {
      s.send("HTTP/1.1 200\r\nConnection: Keep-Alive\r\nKeep-Alive: timeout=60, max=1000\r\nContent-Type: application/dns-message\r\nContent-Length:" + data.length + "\r\n");
    }
    if ( dns_decode_level > 0 ) {
      packet = dns.parse_packet(data);
      dns.parse_question(packet);
      dns_name = packet.question.name;
      s.send("X-DNS-Question: " + dns_name + "\r\n");
      s.send("X-DNS-Type: " + dns.dns_type.value[packet.question.type] + "\r\n");
      s.send("X-DNS-Result: " + dns.dns_codes.value[packet.codes & 0x0f] + "\r\n");
    } 
    if ( dns_decode_level > 1 ) {
      if ( dns_decode_level == 2  ) {
        dns.parse_answers(packet, 2);
      } else if ( dns_decode_level > 2 ) { 
        dns.parse_complete(packet, 2);
      }
      debug(s, "DNS Res Answers: " + JSON.stringify( Object.entries(packet.answers)) );
      if ( "min_ttl" in packet ) {
        cache_time = packet.min_ttl;
        s.send("X-DNS-TTL: " + packet.min_ttl + "\r\n");
      }

      if ( packet.an > 0 ) {
        packet.answers.forEach( function(r) { answers += "[" + dns.dns_type.value[r.type] + ":" + r.data + "]," })
        answers.slice(0,-1);
      } else {
        answers = "[]";
      }
      s.send("X-DNS-Answers: " +  answers + "\r\n");
    }

    debug(s, "DNS Res Packet: " + JSON.stringify( Object.entries(packet)) );
    var d = new Date( Date.now() + (cache_time*1000) ).toUTCString();
    if ( ! d.includes(",") ) {
      d = d.split(" ")
      d = [d[0] + ',', d[2], d[1], d[3], d[4], d[5]].join(" ");
    }
    s.send("Cache-Control: public, max-age=" + cache_time + "\r\n" );
    s.send("Expires: " + d + "\r\n" );

    s.send("\r\n");
    s.send( data, {flush: true} );
    if ( dns_question_balancing ) {
      s.done();
    }
  });
}

/**
 *  Function to perform testing of DNS packet generation for various DNS types
**/
function test_dns_responder(s, data, packet) {
  debug(s,"Testing: DNS Req Name: " + packet.question.name);
  var answers = [];
  if ( packet.question.type == dns.dns_type.A ) {
    answers.push( {name: packet.question.name, type: dns.dns_type.A, class: dns.dns_class.IN, ttl: 300, rdata: "10.2.3.4" } );
  } else if ( packet.question.type == dns.dns_type.AAAA ) {
    answers.push( {name: packet.question.name, type: dns.dns_type.AAAA, class: dns.dns_class.IN, ttl: 300, rdata: "fe80:0002:0003:0004:0005:0006:0007:0008" } );
  } else if ( packet.question.type == dns.dns_type.CNAME ) {
    answers.push( {name: packet.question.name, type: dns.dns_type.CNAME, class: dns.dns_class.IN, ttl: 300, rdata: "www.foo.bar.baz" } );
  } else if ( packet.question.type == dns.dns_type.NS ) {
    answers.push( {name: packet.question.name, type: dns.dns_type.NS, class: dns.dns_class.IN, ttl: 300, rdata: "ns1.foo.bar.baz" } );
    answers.push( {name: packet.question.name, type: dns.dns_type.NS, class: dns.dns_class.IN, ttl: 300, rdata: "ns2.foo.bar.baz" } );
  } else if ( packet.question.type == dns.dns_type.TXT ) {
    answers.push( {name: packet.question.name, type: dns.dns_type.TXT, class: dns.dns_class.IN, ttl: 300, rdata: ["ns1.foo.bar.baz","1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234567890"] } );
  } else if ( packet.question.type == dns.dns_type.MX ) {
    answers.push( {name: packet.question.name, type: dns.dns_type.MX, class: dns.dns_class.IN, ttl: 300, rdata: { priority: 1, exchange: "mx1.foo.com"} } );
    answers.push( {name: packet.question.name, type: dns.dns_type.MX, class: dns.dns_class.IN, ttl: 300, rdata: { priority: 10, exchange: "mx2.foo.com"} } );
  } else if ( packet.question.type == dns.dns_type.SRV ) {
    answers.push( {name: packet.question.name, type: dns.dns_type.SRV, class: dns.dns_class.IN, ttl: 300, rdata: { priority: 1, weight: 10, port: 443, target: "server1.foo.com"} } );
  } else if ( packet.question.type == dns.dns_type.SOA ) {
    answers.push( {name: packet.question.name, type: dns.dns_type.SOA, class: dns.dns_class.IN, ttl: 300, rdata: { primary: "ns1.foo.com", mailbox: "mb.nginx.com", serial: 2019102801, refresh: 1800, retry: 3600, expire: 826483, minTTL:300} } );
  }
  if ( packet.question.name.endsWith("bar.com") ) {
    dns_response = dns.shortcut_response(data, packet, answers);
  } else {
    packet.flags |= dns.dns_flags.AA | dns.dns_flags.QR;
    packet.codes |= dns.dns_codes.RA;
    packet.authority.push( {name: packet.question.name, type: dns.dns_type.SOA, class: dns.dns_class.IN, ttl: 300, rdata: { primary: "ns1.foo.com", mailbox: "mb.nginx.com", serial: 2019102801, refresh: 1800, retry: 3600, expire: 826483, minTTL:300} });
    packet.additional.push( {name: packet.question.name, type: dns.dns_type.NS, class: dns.dns_class.IN, ttl: 300, rdata: "ns1.foo.bar.baz" } );
    packet.additional.push( {name: packet.question.name, type: dns.dns_type.NS, class: dns.dns_class.IN, ttl: 300, rdata: "ns2.foo.bar.baz" } );
    dns_response = dns.encode_packet(packet);
  }
  if (s.variables.protocol == "TCP" ) {
    dns_response = to_bytes( dns_response.length ) + dns_response;
  }
  debug(s,"Testing: Response: " + dns_response.toString('hex') );
}
