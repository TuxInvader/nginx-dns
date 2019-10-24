import dns from "libdns.js";
export default {get_qname, get_response, preread_doh_request, preread_udp_request, preread_tcp_request, filter_doh_request};

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

function process_doh_request(s, decode, filter) {
  s.on("upload", function(data,flags) {
    if ( data.length == 0 ) {
      return;
    }
    data.split("\r\n").forEach( function(line) {
      var bytes;
      var packet;

      if ( line.toString('hex').startsWith( '0000') ) {
        bytes = line;
      } else if ( line.toString().startsWith("GET /dns-query?dns=") ) {
        bytes = String.bytesFrom(line.slice("GET /dns-query?dns=".length, line.length - " HTTP/1.1".length), "base64url");
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
        if (filter) {
          s.send( to_bytes(bytes.length) );
          s.send( bytes, {flush: true} );
        } else {
          domain_scrub(s, bytes, packet);
          s.done();
        }
      } else {
        if (filter) {
          debug(s, "process_doh_request: DNS Req: " + line.toString() );
          s.send("");
          data = "";
        }
      }
    });
  });
}

function process_dns_request(s, decode, filter, tcp) {
   s.on("upload", function(bytes,flags) {
    if ( bytes.length == 0 ) {
      return;
    }
    var packet;
    if (bytes) {
      if (tcp) {
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
      if (filter) {
        if (tcp) {
          s.send( to_bytes(bytes.length) );
        }
        s.send( bytes, {flush: true} );
      } else {
        domain_scrub(s, bytes, packet);
        s.done();
      }
    }
  });
}

function domain_scrub(s, data, packet) {
  if ( s.variables.server_port == 9953 || s.variables.server_port == 9853 ) {
    debug(s,"Scrubbing: DNS Req Name: " + packet.question.name);
    dns_response = dns.shortcut_nxdomain(data, packet);
    debug(s,"Scrubbed: Response: " + dns_response.toString('hex') );
  } else {
    debug(s,"Scrubbing: DNS Req Name: " + packet.question.name);
    ["blocked", "blackhole"].forEach( function( list ) {
      var blocked = s.variables[ list + "_domains" ];
      if ( blocked ) {
        blocked = blocked.split(',');
        blocked.forEach( function( domain ) {
          if (packet.question.name.endsWith( domain )) {
            dns_response = list;
            debug(s,"Scrubbed: DNS Req Name: " + packet.question.name + ", Reason: " + list);
            return;
          }
        });
      }
    });
  }
}

function preread_udp_request(s) {
  process_dns_request(s, true, false, false);
}

function preread_tcp_request(s) {
  process_dns_request(s, true, false, true);
}

function preread_doh_request(s) {
  process_doh_request(s, true, false);
}

function filter_doh_request(s) {

  if ( dns_decode_level >= 3 ) {
    process_doh_request(s, true, true);
  } else {
    process_doh_request(s, false, true);
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

