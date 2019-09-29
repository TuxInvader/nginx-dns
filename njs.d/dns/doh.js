import dns from "dns.js";
export default {get_dns_name, filter_request};

/**
 * DNS Decode Level
 * 0: No decoding, minimal processing required to strip packet from HTTP wrapper (fastest)
 * 1: Parse DNS Header and Question. We can log the Question, Class, Type, and Result Code
 * 2: As 1, but also parse answers. We can log the answers, and also cache responses in HTTP Content-Cache
 * 3: Very Verbose, log everything as above, but also write packet data to error log (slowest)
**/
var dns_decode_level = 2;

var dns_name = String.bytesFrom([]);

function get_dns_name(s) {
  return dns_name;
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

function filter_request(s) {
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
        bytes = String.bytesFrom(line.slice("GET /dns-query?dns=".length, line.length - " HTTP/1.0".length), "base64url");
      } 

      if (bytes) {
        debug(s, "DNS Req: " + bytes.toString('hex') );
        if ( dns_decode_level >= 3 ) {
          packet = dns.parse_packet(bytes);
          debug(s, "DNS Req ID: " + packet.id );
          dns.parse_question(packet);
          debug(s,"DNS Req Name: " + packet.question.name);
          dns_name = packet.question.name;
        }
        s.send( to_bytes(bytes.length) );
        s.send( bytes );
      } else {
        debug(s, "DNS Req: " + line.toString() );
        s.send("");
        data = "";
      }
    });
  });

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
    s.send("HTTP/1.0 200\r\nConnection: Close\r\nContent-Type: application/dns-message\r\nContent-Length:" + data.length + "\r\n");
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
    s.send(data);
    s.done();
  });
}

