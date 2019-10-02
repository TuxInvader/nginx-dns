import dns from "libdns.js";
export default {filter_udp_request};

/**
 * DNS Decode Level
 * 0: No decoding.
 * 1: Parse DNS Header and Question. We can log the Question, Class, Type, and Result Code
 * 2: As 1, but also parse answers. We can log the answers, and also cache responses in HTTP Content-Cache
 * 3: Very Verbose, log everything as above, but also write packet data to error log (slowest)
**/
var dns_decode_level = 3;

var dns_question = String.bytesFrom([]);
var packet;

function get_dns_question(s) {
  return dns_question;
}

function get_dns_type(s) {
  if ( packet ) {
    return dns.dns_type.value[packet.question.type];
  }
}

function get_dns_result(s) {
  if ( packet ) {
    return dns.dns_codes.value[packet.codes & 0x0f];
  }
}

function get_dns_answers(s) {
  var answers = "[]";
  if ( packet ) {
    if ( packet.an > 0 ) {
      packet.answers.forEach( function(r) { answers += "[" + dns.dns_type.value[r.type] + ":" + r.data + "]," })
      answers.slice(0,-1);
    } 
  }
  return answers;
}

function get_dns_min_ttl(s) {
  if ( "min_ttl" in packet ) {
    return packet.min_ttl;
  } else {
    return 2147483647;
  }
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

function filter_udp_request(s) {

  s.on("upload", function(data,flags) {
    if ( data.length == 0 ) {
      return;
    }
    var bytes = data;
    var packet;

    if (bytes) {
      debug(s, "DNS Req: " + bytes.toString('hex') );
      if ( dns_decode_level >= 1 ) {
        packet = dns.parse_packet(bytes);
        debug(s, "DNS Req ID: " + packet.id );
        dns.parse_question(packet);
        debug(s,"DNS Req Name: " + packet.question.name);
        dns_question = packet.question.name;
      }
      //s.send( to_bytes(bytes.length) );
      s.send( bytes );
    } else {
      debug(s, "DNS Req: " + line.toString() );
      s.send("");
      data = "";
    }
  });

  s.on("download", function(data, flags) {
    if ( data.length == 0 ) {
      return;
    }
    // Drop the TCP length field
    //data = data.slice(2);

    debug(s, "DNS Res: " + data.toString('hex') );
    var packet;
    var answers = "";
    if ( dns_decode_level > 0 ) {
      packet = dns.parse_packet(data);
      dns.parse_question(packet);
      dns_question = packet.question.name;
    } 
    if ( dns_decode_level > 1 ) {
      if ( dns_decode_level == 2  ) {
        dns.parse_answers(packet, 2);
      } else if ( dns_decode_level > 2 ) { 
        dns.parse_complete(packet, 2);
      }
      debug(s, "DNS Res Answers: " + JSON.stringify( Object.entries(packet.answers)) );
    }

    //debug(s, "DNS Res Packet: " + JSON.stringify( Object.entries(packet)) );
    s.send(data);
    s.done();
  });
}

