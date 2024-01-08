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
 * DNS Debug Level
 * Specify the decoding level at which we should log packet data to the error log.
 * Default is level 3 (max decoding)
**/
var dns_debug_level = 3;

/**
 * DNS Question Load Balancing
 * Set this to true, if you want to pick the upstream pool based on the DNS Question.
 * Doing so will disable HTTP KeepAlives for DoH so that we can create a new socket for each query
**/
var dns_question_balancing = false;

// The DNS Question name
var dns_name = Buffer.alloc(0);

function get_qname(s) {
  return dns_name;
}

// The Optional DNS response, this is set when we want to block a specific domain
var dns_response = Buffer.alloc(0);

function get_response(s) {
  return dns_response.toString();
}

// Encode the given number to two bytes (16 bit)
function to_bytes( number ) {
  return Buffer.from( [ ((number>>8) & 0xff), (number & 0xff) ] );
}

function debug(s, msg) {
  if ( dns_decode_level >= dns_debug_level ) {
    s.warn(msg);
  }
}

function process_doh_request(s, decode, scrub) {
  s.on("upstream", function(data,flags) {
    if ( data.length == 0 ) {
      return;
    }
    var bytes;
    var packet;
    if(data.toString('utf8', 0, 3) == "GET") {
      const path = data.toString('utf8', 4, data.indexOf(' ', 4));
      const params = path.split("?")[1]
      const qs = params.split("&");
      qs.some( param => {
        if (param.startsWith("dns=") ) {
          bytes = Buffer.from(param.slice(4), "base64url");
          return true;
        }
        return false;
      });
    }

    if(data.toString('utf8', 0, 4) == "POST") {
      bytes = data.slice(data.indexOf('\r\n\r\n') + 4);
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
}

function process_dns_request(s, decode, scrub) {
   s.on("upstream", function(bytes,flags) {
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
      dns_response = Buffer.concat( [ to_bytes( dns_response.length ), dns_response ]);
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
      dns_response = Buffer.concat( [ to_bytes( dns_response.length ), dns_response ]);
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

  s.on("downstream", function(data, flags) {
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

      if ( dns_decode_level > 1 ) {
        if ( dns_decode_level == 2  ) {
          dns.parse_answers(packet, 2);
        } else if ( dns_decode_level > 2 ) {
          dns.parse_complete(packet, 2);
        }
        //debug(s, "DNS Res Answers: " + JSON.stringify( Object.entries(packet.answers)) );
        if ( "min_ttl" in packet ) {
          cache_time = packet.min_ttl;
          s.send("X-DNS-TTL: " + packet.min_ttl + "\r\n");
        }

        if ( packet.an > 0 ) {
          packet.answers.forEach( function(r) { answers += "[" + dns.dns_type.value[r.type] + ":" + r.rdata + "]," })
          answers.slice(0,-1);
        } else {
          answers = "[]";
        }
        s.send("X-DNS-Answers: " +  answers + "\r\n");
      }
      debug(s, "DNS Res Packet: " + JSON.stringify( Object.entries(packet)) );
    }

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

