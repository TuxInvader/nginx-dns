/**

  BEGIN DNS Functions

**/

export default {dns_type, dns_class, dns_flags, dns_codes, 
                parse_packet, parse_question, parse_answers, 
                parse_complete, parse_resource_record,
                shortcut_response, shortcut_nxdomain,
                gen_new_packet, gen_response_packet, encode_packet}

// DNS Types
var dns_type = Object.freeze({
  A:     1,
  NS:    2,
  CNAME: 5,
  SOA:   6,
  PTR:   12,
  MX:    15,
  TXT:   16,
  AAAA:  28,
  SRV:   33,
  OPT:   41,
  AXFR:  252,
  value: { 1:"A", 2:"NS", 5:"CNAME", 6:"SOA", 12:"PTR", 15:"MX", 16:"TXT",
           28:"AAAA", 33:"SRV", 41:"OPT", 252:"AXFR" }
});

// DNS Classes
var dns_class = Object.freeze({
  IN: 1,
  CS: 2,
  CH: 3,
  HS: 4,
  value: { 1:"IN", 2:"CS", 3:"CH", 4:"HS" }
});

// DNS flags (made up of QR, Opcode (4bits), AA, TrunCation, Recursion Desired)
var dns_flags = Object.freeze({
  QR: 0x80,
  AA: 0x4,
  TC: 0x2,
  RD: 0x1
});

// DNS Codes (made up of RA (Recursion Available), Zero (3bits), Response Code (4bits))
var dns_codes = Object.freeze({
  RA:       0x80,
  Z:        0x70,
  //RCODE:    0xf,
  NOERROR:  0x0,
  FORMERR:  0x1,
  SERVFAIL: 0x2,
  NXDOMAIN: 0x3,
  NOTIMPL:  0x4,
  REFUSED:  0x5,
  value: { 0x80:"RA", 0x70:"Z", 0x0:"NOERROR", 0x1:"FORMERR", 0x2:"SERVFAIL", 0x3:"NXDOMAIN", 0x4:"NOTIMPL", 0x5:"REFUSED" }
});

// Convert two bytes in a packet to a 16bit int
function to_int(A, B) {
  return (((A & 0xFF) << 8) | (B & 0xFF));
}

// Convert four bytes in a packet to a 32bit int
function to_int32(A, B, C, D) {
  return ( ((A & 0xFF) << 24) | ((B & 0xFF) << 16) | ((C & 0xFF) << 8) | (D & 0xFF) );
}

// Encode the given number to two bytes (16 bit)
function to_bytes( number ) {
  return String.fromCodePoint( ((number>>8) & 0xff), (number & 0xff) ).toBytes();
}

// Encode the given number to 4 bytes (32 bit)
function to_bytes32( number ) {
  return String.fromCodePoint( (number>>24)&0xff, (number>>16)&0xff, (number>>8)&0xff, number&0xff ).toBytes();
}

// Create a new empty DNS packet structure
function gen_new_packet(id, flags, codes) {
  var dns_packet = { id: id, flags: flags, codes: codes, qd: 0, an: 0, ns: 0, ar: 0,
    question: {},
    answers: [],
    authority: [],
    additional: []
  };
  return dns_packet;
}

/** Create a new response packet suitable as a reply to the given request
 *  You should also supply some answers, authority and/or additional records
 *  in arrays to populate the various sections.
**/
function gen_response_packet( request, question, answers, authority, additional ) {
  var response = gen_new_packet(request.id, request.flags, request.codes);
  response.flags |= dns_flags.AA + dns_flags.QR;
  response.codes |= dns_codes.RA;
  if ( question == null ) {
    response.qd = 0;
  } else {
    response.qd = 1;
    response.question = request.question;
  }
  answers.forEach( function(answer) {
    response.an++;
    response.answers.push( answer );
  });
  return response;
}

/** Encode the provided packet, converting it from the javascript object structure into a bytestring
 *  Returns a bytestring suitable for dropping into a UDP packet, or returning to NGINX
**/
function encode_packet( packet ) {
  var encoded = to_bytes( packet.id );
  encoded += String.fromCodePoint( packet.flags ).toBytes();
  encoded += String.fromCodePoint( packet.codes ).toBytes();
  encoded += to_bytes( packet.qd ); // Questions
  encoded += to_bytes( packet.an ); // Answers
  encoded += to_bytes( packet.ns ); // Authority
  encoded += to_bytes( packet.ar ); // Additional
  encoded += encode_question(packet);
  packet.answers.forEach( function(answer) {
    encoded += gen_resource_record(packet, packet.question.name, dns_type.A, dns_class.IN, 600, "127.0.0.1");
  });
  return encoded;
}

/** Don't mess about. This is a shortcut for responding to DNS Queries. We copy the question out of the query
 *  and cannibalise the original request to generate our response.
**/
function shortcut_response(data, packet, answers) {
  var response = String.bytesFrom([]);
  response += data.slice(0, 2);
  response += String.fromCodePoint( packet.flags |= dns_flags.AA + dns_flags.QR ).toBytes();
  response += String.fromCodePoint( packet.codes ).toBytes();
  response += to_bytes( 1 ); // Questions
  response += to_bytes( answers.length ); // Answers
  response += to_bytes( 0 ); // Authority
  response += to_bytes( 0 ); // Additional
  response += data.slice(12, packet.question.qend );
  answers.forEach( function(answer) {
    response += gen_resource_record(packet, answer.name, answer.type, answer.class, answer.ttl, answer.rdata);
  });
  return response;
}

function shortcut_nxdomain(data, packet) {
  var response = String.bytesFrom([]);
  response += data.slice(0,2);
  response += String.fromCodePoint( packet.flags |= dns_flags.AA + dns_flags.QR ).toBytes();
  response += String.fromCodePoint( packet.codes |= dns_codes.NXDOMAIN ).toBytes();
  response += to_bytes( 1 ); // Questions
  response += to_bytes( 0 ); // Answers
  response += to_bytes( 0 ); // Authority
  response += to_bytes( 0 ); // Additional
  response += data.slice(12, packet.question.qend );
  return response;
}

/** Encode a question object into a bytestring suitable for use in a UDP packet
**/
function encode_question(packet) {
    var encoded = encode_label(packet.question.name);
    encoded += to_bytes(packet.question.type);
    encoded += to_bytes(packet.question.class);
    return encoded;
}

/**
 *  Parse an incoming request bytestring into a DNS packet object. This function decodes the first 12 bytes of the headers.
 *  You will probably want to call parse_question() next.
**/
function parse_packet(data) {
  var packet = { id: to_int(data.codePointAt(0), data.codePointAt(1)), flags: data.codePointAt(2), codes: data.codePointAt(3), min_ttl: 2147483647,
    qd: to_int(data.codePointAt(4), data.codePointAt(5)), an: to_int(data.codePointAt(6), data.codePointAt(7)), ns: to_int(data.codePointAt(8), data.codePointAt(9)),
    ar: to_int(data.codePointAt(10), data.codePointAt(11)), data: data.slice(12), question: [], answers:[], authority: [], additional: [], offset: 0 };
  return packet;
}

/**
 *  Parse the question section of a DNS request packet, adds the QNAME, QTYPE, and QCLASS to the packet object, and stores the
 *  offset in the packet for processing any further sections.
**/
function parse_question(packet) {

  /** QNAME, QTYPE, QCLASS **/

  var name = parse_label(packet);
  packet.question = { name: name, type: to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++)), 
                      class: to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++)), qend: packet.offset + 12 };
  if ( packet.qd != 1 ) {
    return false;
  }
  return true;
}

function parse_answers(packet, decode_level) {
  
  // Process the question section if necessary
  if ( packet.question.length == 0 ) {
    parse_question(packet);
  }

  // Process answers
  if ( packet.an > 0 && packet.answers.length == 0 ) {
    packet.answers = parse_section(packet, packet.an, decode_level);
  }

  // If we didn't have any ttls in the packet, then cache for 5 minutes.
  if (packet.min_ttl == 2147483647) {
    packet.min_ttl = 300;
  }

}


// Parse all sections of the packet
function parse_complete(packet, decode_level) {

  // Process the question section if necessary
  if ( packet.question.length == 0 ) {
    parse_question(packet);
  }

  // Process answers
  if ( packet.an > 0 && packet.answers.length == 0 ) {
    packet.answers = parse_section(packet, packet.an, decode_level);
  }

  // Process authority
  if ( packet.ns > 0 && packet.authority.length == 0) {
    packet.authority = parse_section(packet, packet.ns, decode_level);
  }

  // Process Additional
  if ( packet.ar > 0 && packet.additional.length == 0) {
    packet.additional = parse_section(packet, packet.ar, decode_level);
  }

  // If we didn't have any ttls in the packet, then cache for 5 minutes.
  if (packet.min_ttl == 2147483647) {
    packet.min_ttl = 300;
  }

}

function parse_section(packet, recs, decode_level) {
  var rrs = [];
  for (var i=0; i<recs; i++) {
    var rec = parse_resource_record(packet, decode_level);
    rrs.push(rec);
    if ( rec.ttl < packet.min_ttl ) {
      packet.min_ttl = rec.ttl;
    }
  }
  return rrs;
}

function parse_label(packet) {

  var name = "";
  var compressed = false;
  var pos = packet.offset;
  for ( ; pos < packet.data.length; ) {
    var length = packet.data.codePointAt(pos);
    if (length == 0) {
      // null label, name is finished
      pos++;
      break;
    } else if ( length == 192 ) {
      // compression pointer
      if ( compressed ) {
        pos++;
      } else {
        packet.offset = ++pos + 1;
      }
      pos = packet.data.codePointAt(pos);;
      if ( pos < 12 ) {
        // This shouldn't be possible, the header is 12 bytes so a compression pointer can't be less than 12
        //s.warn("DNS Error - parse_label encountered impossible compression pointer");
        break;
      } else {
        pos = pos - 12;
        compressed = true;
      }
    } else if ( length > 63 ) {
      // Invalid DNS name, individual labels are limited to 63 bytes.
        //s.warn("DNS Error - parse_label encountered invaliad DNS name");
        break;
    } else {
      name += packet.data.slice(++pos, pos+length) + "."; 
      pos += length;
    }
  }

  if ( ! compressed ) {
    packet.offset = pos
  }

  name = name.slice(0,-1);
  return name;
}
 
/** TODO Check sizes on resources/packets
labels          63 octets or less
names           255 octets or less
TTL             positive values of a signed 32 bit number.
UDP messages    512 octets or less
**/

function encode_label( name ) {

  var data = String.bytesFrom([]);
  name.split('.').forEach( function(part){
    data += String.fromCodePoint(part.length);
    data += part;
  });
  data += String.fromCodePoint(0);
  return data;

}

function gen_resource_record(packet, name, type, clss, ttl, rdata) {

  /**
    NAME
    TYPE (2 octets)
    CLASS (2 octects)
    TTL 32bit signed int
    RDLength 16bit int length of RDATA
    RDATA variable length string
  **/

  var resource = "";
  var record = "";

  if ( name == packet.question.name ) {
    // The name matches the query, set a compression pointer.
    resource += String.fromCodePoint(192, 12).toBytes();
  } else {
    // gen labels for the name
    resource += encode_label(name);
  }
  
  resource += String.fromCodePoint(type & 0xff00, type & 0xff);
  switch(type) {
    case dns_type.A:
      record = encode_arpa_v4(rdata);
      break;
    case dns_type.AAAA:
      record = encode_arpa_v6(rdata);
      break;
    case dns_type.NS:
      record = encode_label(rdata);
      break;
    case dns_type.CNAME:
      record = encode_label(rdata);
      break;
    case dns_type.SOA:
      record = encode_soa_record(rdata);
      break;
    case dns_type.SRV:
      record = encode_srv_record(rdata);
      break;
    case dns_type.MX:
      record = encode_mx_record(rdata);
      break;
    case dns_type.TXT:
      record = encode_txt_record(rdata);
      break;
    default:
      //TODO Barf
  }

  switch(clss) {
    case dns_class.IN:
      resource += String.fromCodePoint(0,1).toBytes();
      break;
    default:
      //TODO Barf
      resource += String.fromCodePoint(99,99).toBytes();
  }

  resource += to_bytes32(ttl);
  resource += to_bytes( record.length );
  resource += record;
  return resource;
}

// Process resource records, to a varying depth dictated by decode_level
// decode_level {0: name+type, 1: name+type+class+ttl, 2: everything}
function parse_resource_record(packet, decode_level) {

  /**
    NAME
    TYPE (2 octets)
    CLASS (2 octects)
    TTL 32bit signed int
    RDLength 16bit int length of RDATA
    RDATA variable length string
  **/

  var resource = {}
  resource.name = parse_label(packet);
  resource.type = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));

  if ( decode_level > 0 ) {
    if (resource.type == dns_type.OPT ) {
      // EDNS
      parse_edns_options(packet);
    } else {
      resource.class = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
      resource.ttl = to_int32(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++),
                              packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
      resource.rdlength = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
      if ( decode_level == 1 ) {
        resource.data = packet.data.slice(packet.offset, packet.offset + resource.rdlength);
        packet.offset += resource.rdlength;
      } else {
        switch(resource.type) {
          case dns_type.A:
            resource.data = parse_arpa_v4(packet, resource);
            break;
          case dns_type.AAAA:
            resource.data = parse_arpa_v6(packet, resource);
            break;
          case dns_type.NS:
            resource.data = parse_label(packet);
            break;
          case dns_type.CNAME:
            resource.data = parse_label(packet);
            break;
          case dns_type.SOA:
            resource.data = parse_soa_record(packet);
            break;
          case dns_type.SRV:
            resource.data = parse_srv_record(packet);
            break;
          case dns_type.MX:
            resource.data = parse_mx_record(packet);
            break;
          case dns_type.TXT:
            resource.data = parse_txt_record(packet, resource.rdlength);
            break;
          default:
            resource.data = packet.data.slice(packet.offset, packet.offset + resource.rdlength);
            packet.offset += resource.rdlength;
        }
      }
    }
  }
  return resource;
}

function encode_arpa_v4( ipv4 ) {
  var rdata = "";
  ipv4.split('\.').forEach( function(octet) {
    rdata += String.fromCodePoint( octet ).toBytes();
  });
  return rdata;
}

function parse_arpa_v4(packet) {
  var octet = [0,0,0,0];
  for (var i=0; i< 4 ; i++ ) {
    octet[i] = packet.data.codePointAt(packet.offset++);
  }
  return octet.join(".");
}

function encode_arpa_v6( ipv6 ) {
  var rdata = "";
  ipv6.split(':').forEach( function(segment) {
    rdata += String.bytesFrom(segment[0] + segment[1], 'hex');
    rdata += String.bytesFrom(segment[2] + segment[3], 'hex');
  });
  return rdata;
}

function parse_arpa_v6(packet) {
  var ipv6 = "";
  for (var i=0; i<8; i++ ) {
    var a = packet.data.charCodeAt(packet.offset++).toString(16);
    var b = packet.data.charCodeAt(packet.offset++).toString(16);
    ipv6 += a + b + ":";
  }
  return ipv6.slice(0,-1);
}

function encode_txt_record( text_array ) {
  var rdata = String.bytesFrom([]);
  text_array.forEach( function(text) {
    var tl = text.length;
    if ( tl > 255 ) {
      for (var i=0 ; i < tl ; i++ ) {
        var len = (tl > (i+255)) ? 255 : tl - i;
        rdata += String.fromCodePoint(len).toBytes();
        rdata += text.slice(i,i+len);
        i += len;
      }
    } else { 
      rdata += String.fromCodePoint(tl).toBytes();
      rdata += text;
    }
  });
  return rdata;
}

function parse_txt_record(packet, length) {
  var txt = [];
  var pos = 0;
  while ( pos < length ) {
    var tl = packet.data.codePointAt(packet.offset++);
    txt.push( packet.data.slice(packet.offset, packet.offset + tl));
    pos += tl + 1;
    packet.offset += tl;
  }
  return txt;
}

function encode_mx_record( mx ) {
  var rdata = String.bytesFrom([]);
  rdata += to_bytes( mx.priority );
  rdata += encode_label( mx.exchange );
  return rdata;
}

function parse_mx_record(packet) {
  var mx = {};
  mx.priority = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
  mx.exchange = parse_label(packet);
  return mx;
}

function encode_srv_record( srv ) {
  var rdata = String.bytesFrom([]);
  rdata += to_bytes( srv.priority );
  rdata += to_bytes( srv.weight );
  rdata += to_bytes( srv.port );
  rdata += encode_label( srv.target );
  return rdata;
}

function parse_srv_record(packet) {
  var srv = {};
  srv.priority = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
  srv.weight = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
  srv.port = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
  srv.target = parse_label(packet);
  return srv;
}

function encode_soa_record( soa ) {
  var rdata = String.bytesFrom([]);
  rdata += encode_label(soa.primary);
  rdata += encode_label(soa.mailbox);
  rdata += to_bytes32(soa.serial);
  rdata += to_bytes32(soa.refresh);
  rdata += to_bytes32(soa.retry);
  rdata += to_bytes32(soa.expire);
  rdata += to_bytes32(soa.minTTL);
  return rdata;
}

function parse_soa_record(packet) {
  var soa = {};
  soa.primary = parse_label(packet);
  soa.mailbox = parse_label(packet);
  soa.serial = to_int32(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++),
               packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
  soa.refresh = to_int32(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++),
               packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
  soa.retry = to_int32(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++),
               packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
  soa.expire = to_int32(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++),
               packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
  soa.minTTL = to_int32(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++),
               packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
  return soa;
}

function parse_edns_options(packet) {

  packet.edns = {}
  packet.edns.opts = {}
  packet.edns.size = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
  packet.edns.rcode = packet.data.codePointAt(packet.offset++);
  packet.edns.version = packet.data.codePointAt(packet.offset++);
  packet.edns.z = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
  packet.edns.rdlength = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));

  var end = packet.offset + packet.edns.rdlength;
  for ( ; packet.offset < end ; ) {
    var opcode = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
    var oplength = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
    if ( opcode == 8 ) {
      //client subnet
      packet.edns.opts.csubnet = {}
      packet.edns.opts.csubnet.family = to_int(packet.data.codePointAt(packet.offset++), packet.data.codePointAt(packet.offset++));
      packet.edns.opts.csubnet.netmask = packet.data.codePointAt(packet.offset++);
      packet.edns.opts.csubnet.scope = packet.data.codePointAt(packet.offset++);
      if ( packet.edns.opts.csubnet.family == 1 ) {
        // IPv4
        var octet = [0,0,0,0];
        for (var i=4; i< oplength ; i++ ) {
          octet[i-4] = packet.data.codePointAt(packet.offset++);
        }
        packet.edns.opts.csubnet.subnet = octet.join(".");
        break;
      } else {
        // We don't support IPv6 yet.
        packet.edns.opts = {}
        break;
      }
    } else {
      // We only look for CSUBNET... Not interested in anything else at this time.
      packet.offset += oplength;
    }
  }

}


