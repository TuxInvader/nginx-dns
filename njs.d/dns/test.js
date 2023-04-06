
import dns from "libdns.js";
export default {get_qname, test_dns_encoder, test_dns_decoder};

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

// The DNS Question name
var dns_name = Buffer.alloc(0);

function get_qname(s) {
  return dns_name;
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

function test_dns_encoder(s) {
  s.on("upstream", function(data,flags) {
    var packet;
    var test_result = Buffer.alloc(0);
    if ( data.length == 0 ) {
      return;
    }
    if (data) {
      if (s.variables.protocol == "TCP") {
        // Drop the TCP length field
        data = data.slice(2);
      }
      debug(s, "test_dns: DNS Encoder Req: " + data.toString('hex') );
      packet = dns.parse_packet(data);
      dns.parse_question(packet);
      dns_name = packet.question.name;
      debug(s, "test_dns: DNS Encoder Request Packet: " + JSON.stringify( Object.entries(packet)) );
      test_result = test_dns_responder(s, data, packet);
      delete packet.data; // remove the data buffer before printing
      debug(s, "test_dns: DNS Encoder Response Packet: " + JSON.stringify( Object.entries(packet)) );
      debug(s, "test_dns: DNS Encoder Res: " + test_result.toString('hex') );
      s.variables.test_result = test_result;
      s.done();
    }
  });
}


function test_dns_decoder(s) {
  s.on("downstream", function(data,flags) {
    var packet;
    var test_result = Buffer.alloc(0);
    if ( data.length == 0 ) {
      return;
    }
    if (data) {
      if (s.variables.protocol == "TCP") {
        // Drop the TCP length field
        data = data.slice(2);
      }
      debug(s, "test_dns: DNS Decoder Res: " + data.toString('hex') );
      packet = dns.parse_packet(data);
      dns.parse_question(packet);
      dns_name = packet.question.name;
      dns.parse_complete(packet, 2);
      delete packet.data; // remove the data buffer before printing
      debug(s, "test_dns: DNS Decoder Response Packet: " + JSON.stringify( Object.entries(packet)) );
      if (s.variables.protocol == "TCP") {
        s.send( to_bytes(data.length) );
      }
      s.send( data, {flush: true} );
    }
  });
}

/**
 *  Function to perform testing of DNS packet generation for various DNS types
 *  Any domain ending bar.com will use the shortcut_response path 
 *  Any domains ending baz.com will use shortcut_nxdomain path
 *  All other queries will return an appropriate set of DNS records.
**/
function test_dns_responder(s, data, packet) {
  var answers = [];
  var test_result;

  if ( packet.question.type == dns.dns_type.A || packet.question.type == dns.dns_type.ANY ) {
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

  if ( packet.question.name.toString().endsWith("bar.com") ) {
    test_result = dns.shortcut_response(data, packet, answers);
  } else if ( packet.question.name.toString().endsWith("baz.com") ) {
    test_result = dns.shortcut_nxdomain(data, packet);
  } else {
    packet.flags |= dns.dns_flags.AA | dns.dns_flags.QR;
    packet.codes |= dns.dns_codes.RA;
    packet.authority.push( {name: packet.question.name, type: dns.dns_type.SOA, class: dns.dns_class.IN, ttl: 300, rdata: { primary: "ns1.foo.com", mailbox: "mb.nginx.com", serial: 2019102801, refresh: 1800, retry: 3600, expire: 826483, minTTL:300} });
    packet.additional.push( {name: packet.question.name, type: dns.dns_type.NS, class: dns.dns_class.IN, ttl: 300, rdata: "ns1.foo.bar.baz" } );
    packet.additional.push( {name: packet.question.name, type: dns.dns_type.NS, class: dns.dns_class.IN, ttl: 300, rdata: "ns2.foo.bar.baz" } );
       packet.answers = answers;
    test_result = dns.encode_packet(packet);
  }
  if (s.variables.protocol == "TCP" ) {
    test_result = Buffer.concat( [ to_bytes( test_result.length ), test_result ]);
  }
  return test_result;
}

