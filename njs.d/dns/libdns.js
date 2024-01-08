/**

  BEGIN DNS Functions

**/

export default {dns_type, dns_class, dns_flags, dns_codes,
                edns_opcode, is_ipv4,
                parse_packet, parse_question, parse_answers,
                parse_complete, parse_resource_record,
                shortcut_response, shortcut_nxdomain,
                gen_new_packet, gen_response_packet, encode_packet}

// DNS Types
const dns_type = Object.freeze({
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
  HTTPS: 65,
  AXFR:  252,
  ANY:   255,
  value: { 1:"A", 2:"NS", 5:"CNAME", 6:"SOA", 12:"PTR", 15:"MX", 16:"TXT",
           28:"AAAA", 33:"SRV", 41:"OPT", 65:"HTTPS", 252:"AXFR", 255:"ANY" }
});

// DNS Classes
const dns_class = Object.freeze({
  IN: 1,
  CS: 2,
  CH: 3,
  HS: 4,
  value: { 1:"IN", 2:"CS", 3:"CH", 4:"HS" }
});

// DNS flags (made up of QR, Opcode (4bits), AA, TrunCation, Recursion Desired)
const dns_flags = Object.freeze({
  QR: 0x80,
  AA: 0x4,
  TC: 0x2,
  RD: 0x1
});

// DNS Codes (made up of RA (Recursion Available), Zero (3bits), Response Code (4bits))
const dns_codes = Object.freeze({
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

// EDNS opcodes (see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
const edns_opcode = Object.freeze({
  LLQ:       1,
  UL:        2,
  NSID:      3,
  DAU:       5,
  DHU:       6,
  N3U:       7,
  CSUBNET:   8,
  EXPIRE:    9,
  COOKIE:    10,
  KEEPALIVE: 11,
  PADDING:   12,
  CHAIN:     13,
  KEYTAG:    14,
  ERROR:     15,
  CLIENTTAG: 16,
  SERVERTAG: 17,
  UMBRELLA:  20292,
  DEVICEID:  26946,
  value: { 1:"LLQ", 2:"UL", 3:"NSID", 5:"DAU", 6:"DHU", 7:"N3U", 8:"CSUBNET", 9:"EXPIRE", 10:"COOKIE", 11:"KEEPALIVE", 12:"PADDING", 13:"CHAIN", 14:"KEYTAG", 15:"ERROR", 16:"CLIENTTAG", 17:"SERVERTAG", 20292:"UMBRELLA", 26946:"DEVICEID" }
});

// Encode the given number to two bytes (16 bit)
function to_bytes( number ) {
  return Buffer.from( [ ((number>>8) & 0xff), (number & 0xff) ] );
}

// Encode the given number to 4 bytes (32 bit)
function to_bytes32( number ) {
  return Buffer.from( [ (number>>24)&0xff, (number>>16)&0xff, (number>>8)&0xff, number&0xff ] );
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
  var encoded = Buffer.from( to_bytes( packet.id ) );
  encoded = Buffer.concat( [ encoded, Buffer.from([ packet.flags ])] );
  encoded = Buffer.concat( [ encoded, Buffer.from([ packet.codes ])] );
  encoded = Buffer.concat( [ encoded, Buffer.from( to_bytes( packet.qd ))] ); // Questions
  encoded = Buffer.concat( [ encoded, Buffer.from( to_bytes( packet.answers.length ))] ); // Answers
  encoded = Buffer.concat( [ encoded, Buffer.from( to_bytes( packet.authority.length ))] ); // Authority
  encoded = Buffer.concat( [ encoded, Buffer.from( to_bytes( packet.additional.length ))] ); // Additional
  encoded = Buffer.concat( [ encoded, encode_question(packet) ]);
  packet.answers.forEach( function(answer) {
    encoded = Buffer.concat( [ encoded, gen_resource_record(packet, answer.name, answer.type, answer.class, answer.ttl, answer.rdata) ]);
  });
  packet.authority.forEach( function(auth) {
    encoded = Buffer.concat( [ encoded, gen_resource_record(packet, auth.name, auth.type, auth.class, auth.ttl, auth.rdata)] );
  });
  packet.additional.forEach( function(adtnl) {
    encoded = Buffer.concat( [ encoded, gen_resource_record(packet, adtnl.name, adtnl.type, adtnl.class, adtnl.ttl, adtnl.rdata)] );
  });
  encoded = Buffer.concat( [ encoded, gen_edns_options(packet) ] ); // EDNS options (a special additional record of dns_type.OPT)
  return encoded;
}

/** Don't mess about. This is a shortcut for responding to DNS Queries. We copy the question out of the query
 *  and cannibalise the original request to generate our response.
**/
function shortcut_response(data, packet, answers) {
  var response = Buffer.alloc(0);
  response = Buffer.concat( [ response, data.slice(0,2) ] );
  response = Buffer.concat( [ response, Buffer.from([ (packet.flags |= dns_flags.AA | dns_flags.QR) ])] );
  response = Buffer.concat( [ response, Buffer.from([ (packet.codes |= dns_codes.RA) ])] );
  // append counts: qd, answer count, 0 auths, 0 additional
  response = Buffer.concat( [ response, Buffer.from([ 0x00, 0x01 ]), Buffer.from( to_bytes(answers.length)), Buffer.from( [0x0, 0x0, 0x0, 0x0 ]) ] );
  response = Buffer.concat( [ response, data.slice(12, packet.question.qend ) ] );
  answers.forEach( function(answer) {
    response = Buffer.concat( [ response, gen_resource_record(packet, answer.name, answer.type, answer.class, answer.ttl, answer.rdata) ]);
  });
  return response;
}

function shortcut_nxdomain(data, packet) {
  var response = Buffer.alloc(0);
  response = Buffer.concat( [ response, data.slice(0,2) ] );
  response = Buffer.concat( [ response, Buffer.from([ (packet.flags |= dns_flags.AA | dns_flags.QR) ])] );
  response = Buffer.concat( [ response, Buffer.from([ (packet.codes |= dns_codes.NXDOMAIN | dns_codes.RA) ])] );
  // append counts: qd, answer count, 0 auths, 0 additional
  response = Buffer.concat( [ response, Buffer.from([ 0x00, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 ]) ] );
  response = Buffer.concat( [ response, data.slice(12, packet.question.qend ) ] );
  return response;
}

/** Encode a question object into a bytestring suitable for use in a UDP packet
**/
function encode_question(packet) {
    var encoded = Buffer.from( encode_label(packet.question.name) );
    encoded = Buffer.concat( [ encoded, Buffer.from(to_bytes(packet.question.type)), Buffer.from(to_bytes(packet.question.class)) ] );
    return encoded;
}

/**
 *  Parse an incoming request bytestring into a DNS packet object. This function decodes the first 12 bytes of the headers.
 *  You will probably want to call parse_question() next.
**/
function parse_packet(data) {
  var packet = { id: data.readUInt16BE(0), flags: data[2], codes: data[3], min_ttl: 2147483647,
    qd: data.readUInt16BE(4), an: data.readUInt16BE(6), ns: data.readUInt16BE(8),
    ar: data.readUInt16BE(10), data: data.slice(12), question: [], answers:[], authority: [], additional: [], offset: 0 };
  return packet;
}

/**
 *  Parse the question section of a DNS request packet, adds the QNAME, QTYPE, and QCLASS to the packet object, and stores the
 *  offset in the packet for processing any further sections.
**/
function parse_question(packet) {

  /** QNAME, QTYPE, QCLASS **/

  var name = parse_label(packet);
  packet.question = { name: name, type: packet.data.readUInt16BE(packet.offset), 
                      class: packet.data.readUInt16BE(packet.offset+2), qend: packet.offset + 16 };
  packet.offset += 4;
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
    var length = packet.data[pos];
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
      pos = packet.data[pos];;
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

  var data = Buffer.alloc(0);
  name.split('.').forEach( function(part){
    data = Buffer.concat( [ data, Buffer.from([ part.length ]), Buffer.from(part) ] );
  });
  data = Buffer.concat( [data, Buffer.from([0]) ]);
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

  var resource;
  var record = "";

  if ( type == dns_type.OPT ) {
    // skip EDNS here - it should be triggered already in the calling function
    return Buffer.alloc(0);
  }
  else if ( name == packet.question.name ) {
    // The name matches the query, set a compression pointer.
    resource = Buffer.from([192, 12]);
  } else {
    // gen labels for the name
    resource = encode_label(name);
  }

  resource = Buffer.concat( [ resource, Buffer.from([ type & 0xff00, type & 0xff ]) ]);
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
      resource = Buffer.concat([ resource, Buffer.from( [ 0, 1 ] )]);
      break;
    default:
      //TODO Barf
      resource = Buffer.concat([ resource, Buffer.from( [ 99, 99 ] )]);
  }

  resource = Buffer.concat( [ resource, Buffer.from(to_bytes32(ttl)) ] );
  resource = Buffer.concat( [ resource, Buffer.from(to_bytes( record.length )) ] );
  resource = Buffer.concat( [ resource, Buffer.from(record) ] );
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
  resource.type = packet.data.readUInt16BE(packet.offset);
  packet.offset += 2;

  if ( decode_level > 0 ) {
    if (resource.type == dns_type.OPT ) {
      // EDNS
      parse_edns_options(packet);
    } else {
      resource.class = packet.data.readUInt16BE(packet.offset);
      resource.ttl = packet.data.readUInt32BE(packet.offset+2);
      resource.rdlength = packet.data.readUInt16BE(packet.offset+6);
      packet.offset +=8;
      if ( decode_level == 1 ) {
        resource.rdata = packet.data.slice(packet.offset, packet.offset + resource.rdlength);
        packet.offset += resource.rdlength;
      } else {
        switch(resource.type) {
          case dns_type.A:
            resource.rdata = parse_arpa_v4(
              packet.data.slice(packet.offset, packet.offset + resource.rdlength)
	    );
            packet.offset += resource.rdlength;
            break;
          case dns_type.AAAA:
            resource.rdata = parse_arpa_v6(
              packet.data.slice(packet.offset, packet.offset + resource.rdlength)
	    );
            packet.offset += resource.rdlength;
            break;
          case dns_type.NS:
            resource.rdata = parse_label(packet);
            break;
          case dns_type.CNAME:
            resource.rdata = parse_label(packet);
            break;
          case dns_type.SOA:
            resource.rdata = parse_soa_record(packet);
            break;
          case dns_type.SRV:
            resource.rdata = parse_srv_record(packet);
            break;
          case dns_type.MX:
            resource.rdata = parse_mx_record(packet);
            break;
          case dns_type.TXT:
            resource.rdata = parse_txt_record(packet, resource.rdlength);
            break;
          default:
            resource.rdata = packet.data.slice(packet.offset, packet.offset + resource.rdlength);
            packet.offset += resource.rdlength;
        }
      }
    }
  }
  return resource;
}

function is_ipv4(ip) {
  // Determine if IP is IPv4 (true) or IPv6 (false)
  const segments = ip.split('\.');
  return (segments.length == 4 &&
          segments.every(s => (s >= 0 && s <= 255)));
}

function encode_arpa_v4( ipv4 ) {
  var rdata = Buffer.alloc(4);
  var index = 0;
  ipv4.split('\.').forEach( function(octet) {
    rdata[index++] = octet;
  });
  return rdata;
}

function parse_arpa_v4(rdata) {
  var octet = [0,0,0,0];
  for (var i=0; i < rdata.length; i++ ) {
    octet[i] = rdata[i];
  }
  return octet.join(".");
}

function encode_arpa_v6( ipv6 ) {
  var rdata = Buffer.alloc(0);
  // expand :: to up to 7 : separators
  const n = 7 - ipv6.match(/:/g).length;
  ipv6 = ipv6.replace('::', ':'.repeat(n + 2));
  ipv6.split(':').forEach( function(segment) {
    while ( segment.length < 4 ) {
      segment = "0" + segment;
    }
    rdata = Buffer.concat( [ rdata, Buffer.from( segment[0] + segment[1], 'hex') ] );
    rdata = Buffer.concat( [ rdata, Buffer.from( segment[2] + segment[3], 'hex') ] );
  });
  return rdata;
}

function parse_arpa_v6(rdata) {
  var ipv6 = "";
  var segment;
  for ( var i = 0; i < rdata.length; i += 2 ) {
    segment = rdata.toString('hex', i, i + 2);
    if ( segment.length <= 2 ) {
      // padding for sparse subnet (i.e. /120)
      segment += "00";
    }
    ipv6 += segment + ":";
  }
  if ( rdata.length <= 112 ) {
    ipv6 += ":";
  } else {
    ipv6 = ipv6.slice(0, -1);
  }
  return ipv6;
}

function encode_txt_record( text_array ) {
  var rdata = Buffer.alloc(0);
  text_array.forEach( function(text) {
    var tl = text.length;
    if ( tl > 255 ) {
      for (var i=0 ; i < tl ; i++ ) {
        var len = (tl > (i+255)) ? 255 : tl - i;
        rdata = Buffer.concat( [ rdata, Buffer.from([len]), Buffer.from(text.slice(i,i+len)) ] );
        i += len;
      }
    } else { 
      rdata = Buffer.concat( [ rdata, Buffer.from([tl]), Buffer.from(text) ] );
    }
  });
  return rdata;
}

function parse_txt_record(packet, length) {
  var txt = [];
  var pos = 0;
  while ( pos < length ) {
    var tl = packet.data[packet.offset++];
    txt.push( packet.data.toString('utf8', packet.offset, packet.offset + tl));
    pos += tl + 1;
    packet.offset += tl;
  }
  return txt;
}

function encode_mx_record( mx ) {
  var rdata = Buffer.alloc(0);
  rdata += to_bytes( mx.priority );
  rdata += encode_label( mx.exchange );
  return rdata;
}

function parse_mx_record(packet) {
  var mx = {};
  mx.priority = packet.data.readUInt16BE(packet.offset);
  packet.offset += 2;
  mx.exchange = parse_label(packet);
  return mx;
}

function encode_srv_record( srv ) {
  var rdata = Buffer.alloc(6)
  rdata.writeInt16BE( srv.priority, 0 );
  rdata.writeInt16BE( srv.weight, 2 );
  rdata.writeInt16BE( srv.port, 4 );
  rdata = Buffer.concat( [ rdata, encode_label( srv.target ) ]);
  return rdata;
}

function parse_srv_record(packet) {
  var srv = {};
  srv.priority = packet.data.readUInt16BE(packet.offset);
  srv.weight = packet.data.readUInt16BE(packet.offset+2);
  srv.port = packet.data.readUInt16BE(packet.offset+4);
  packet.offset += 6;
  srv.target = parse_label(packet);
  return srv;
}

function encode_soa_record( soa ) {
  var rdata = Buffer.concat([ encode_label(soa.primary), encode_label(soa.mailbox) ]);
  rdata = Buffer.concat( [ rdata, Buffer.from(to_bytes32(soa.serial)), Buffer.from(to_bytes32(soa.refresh)), 
          Buffer.from(to_bytes32(soa.retry)), Buffer.from(to_bytes32(soa.expire)), Buffer.from(to_bytes32(soa.minTTL)) ]);
  return rdata;
}

function parse_soa_record(packet) {
  var soa = {};
  soa.primary = parse_label(packet);
  soa.mailbox = parse_label(packet);
  soa.serial  = packet.data.readUInt32BE(packet.offset);
  soa.refresh = packet.data.readUInt32BE(packet.offset+=4);
  soa.retry   = packet.data.readUInt32BE(packet.offset+=4);
  soa.expire  = packet.data.readUInt32BE(packet.offset+=4);
  soa.minTTL  = packet.data.readUInt32BE(packet.offset+=4);
  packet.offset +=4;
  return soa;
}

function parse_edns_options(packet) {

  /**
    NAME                                    '' (name: root)
    TYPE (2 bytes)                          41 (type: OPT)
    UDP payload size (2 bytes)              .. (UDP payload size)
    EDNS rcode (1 byte)                     0
    ENDS version (1 byte)                   0
    RESERVED 16bit                          0
    RDLength 16bit int length of RDATA
    RDATA variable length string containing 0, 1 or multiple
      . OPCODE (2 bytes)
      . OPLENGTH (2 bytes)
      . OPDATA (variable length)
  **/

  packet.edns = {
    opts: {},
    size: packet.data.readUInt16BE(packet.offset),
    rcode: packet.data[packet.offset+2],
    version: packet.data[packet.offset+3],
    z: packet.data.readUInt16BE(packet.offset+4),
    rdlength: packet.data.readUInt16BE(packet.offset+6)
  };
  packet.offset += 8;

  const end = packet.offset + packet.edns.rdlength;
  while ( packet.offset < end ) {
    var opcode = packet.data.readUInt16BE(packet.offset);
    var oplength = packet.data.readUInt16BE(packet.offset+2);
    packet.offset += 4;
    if ( opcode == edns_opcode.CSUBNET ) {
      // CSUBNET
      const _family = packet.data.readUInt16BE(packet.offset);
      const parse_arpa = (_family == 1 ? parse_arpa_v4 : parse_arpa_v6);
      packet.edns.opts.csubnet = {
        family: _family,
        netmask: packet.data[packet.offset+2],
        scope: packet.data[packet.offset+3],
        subnet: parse_arpa(
          packet.data.slice(packet.offset+4, packet.offset+oplength)
        )
      };
    } else {
    // COOKIE etc.
      packet.edns.opts[edns_opcode.value[opcode].toLowerCase()] = {
        opdata: packet.data.slice(packet.offset, packet.offset + oplength)
      };
    }
    packet.offset += oplength;
  }
}

function gen_edns_options(packet) {

  /**
    NAME                                    '' (name: root)
    TYPE (2 bytes)                          41 (type: OPT)
    UDP payload size (2 bytes)              .. (UDP payload size)
    EDNS rcode (1 byte)                     0
    ENDS version (1 byte)                   0
    RESERVED 16bit                          0
    RDLength 16bit int length of RDATA
    RDATA variable length string containing 0, 1 or multiple
      . OPCODE (2 bytes)
      . OPLENGTH (2 bytes)
      . OPDATA (variable length)
  **/

  if ( 'edns' in packet ) {
    let rdata = Buffer.alloc(0);
    if ( 'csubnet' in packet.edns.opts ) {
      const encode_arpa = (
        packet.edns.opts.csubnet.family == 1 ?
        encode_arpa_v4 :   // IPv4
	encode_arpa_v6);   // IPv6
      const csubnet = Buffer.concat([
        to_bytes( packet.edns.opts.csubnet.family ),        // i.e. 1  (IPv4)
        Buffer.from([ packet.edns.opts.csubnet.netmask ]),  // i.e. 24 (/24)
        Buffer.from([ packet.edns.opts.csubnet.scope ]),    // i.e. 0
        encode_arpa(packet.edns.opts.csubnet.subnet).slice(
          0,
          Math.ceil(packet.edns.opts.csubnet.netmask/8)
        )                                                   // i.e. 10.2.3.x (hex, truncated to netmask)
      ]);
      rdata = Buffer.concat([ rdata,
        to_bytes(edns_opcode.CSUBNET),
        to_bytes(csubnet.length),
        csubnet
      ]);
    }
    if ( 'cookie' in packet.edns.opts ) {
      rdata = Buffer.concat([ rdata,
        to_bytes(edns_opcode.COOKIE),
        to_bytes(packet.edns.opts.cookie.opdata.length),
        packet.edns.opts.cookie.opdata
      ]);
    }
    // TODO: treat other OPCODEs
    return Buffer.concat([
      Buffer.from([0]),
      to_bytes(dns_type.OPT),
      to_bytes(packet.edns.size || 1232),
      Buffer.from([packet.edns.rcode || 0]),
      Buffer.from([packet.edns.version || 0]),
      to_bytes(packet.edns.z || 0),
      to_bytes(rdata.length),
      rdata
    ]);
  }
}
