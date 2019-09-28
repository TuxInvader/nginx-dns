import dns from "dns.js";
export default {get_dns_name, filter_request};

var dns_name = String.bytesFrom([]);

function get_dns_name(s) {
  return dns_name;
}

// Encode the given number to two bytes (16 bit)
function to_bytes( number ) {
  return String.fromCodePoint( ((number>>8) & 0xff), (number & 0xff) ).toBytes();
}

function filter_request(s) {
  s.on("upload", function(data,flags) {
    if ( data.length == 0 ) {
      return;
    }
    data.split("\r\n").forEach( function(line) {
      if ( line.toString('hex').startsWith( '0000') ) {
        s.warn( "Received: " + line.toString('hex') );
        var packet = dns.parse_packet(line);
        s.warn( "ID: " + packet.id );
        dns.parse_question(packet);
        s.warn("Name: " + packet.question.name);
        dns_name = packet.question.name;
        s.send( to_bytes(line.length) );
        s.send( line );
      } else if ( line.toString().startsWith("GET /dns-query?dns=") ) {
        var bytes = String.bytesFrom(line.slice("GET /dns-query?dns=".length, line.length - " HTTP/1.0".length), "base64url");
        s.warn( "Received: " + bytes.toString('hex') );
        var packet = dns.parse_packet(bytes);
        s.warn( "ID: " + packet.id );
        dns.parse_question(packet);
        s.warn("Name: " + packet.question.name);
        dns_name = packet.question.name;
        s.send( to_bytes(bytes.length) );
        s.send( bytes );
      } else {
        s.warn( "Received: " + line.toString() );
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
    var packet = dns.parse_packet(data);
    var answers = "";
    dns.parse_complete(packet, 2);
    s.warn( "DNS: " + data.toString('hex') );
    s.warn( "DNS: Answers: " + packet.an );
    s.warn( "DNS: Packet: " + JSON.stringify( Object.entries(packet)) );
    //s.warn( JSON.stringify( Object.entries(packet.question)) );
    //s.warn( JSON.stringify( Object.entries(packet.answers)) );
    s.send("HTTP/1.0 200\r\nConnection: Close\r\nContent-Type: application/dns-message\r\nContent-Length:" + data.length + "\r\n");
    if ( "min_ttl" in packet ) {
      var d = new Date( Date.now() + (packet.min_ttl*1000) ).toUTCString();
      if ( ! d.includes(",") ) {
        d = d.split(" ")
        d = [d[0] + ',', d[2], d[1], d[3], d[4], d[5]].join(" ");
      }
      s.send("Cache-Control: public, max-age=" + packet.min_ttl + "\r\n" );
      s.send("Expires: " + d + "\r\n" );
    }
    if ( packet.an > 0 ) {
      packet.answers.forEach( function(r) { answers += "[" + dns.dns_type.value[r.type] + ":" + r.data + "]," })
      answers.slice(0,-1);
    } else {
      answers = "[]";
    }
    s.send("X-DNS-Question: " + dns_name + "\r\n");
    s.send("X-DNS-Type: " + dns.dns_type.value[packet.question.type] + "\r\n");
    s.send("X-DNS-Result: " + dns.dns_codes.value[packet.codes & 0x0f] + "\r\n");
    s.send("X-DNS-TTL: " + packet.min_ttl + "\r\n");
    s.send("X-DNS-Answers: " +  answers + "\r\n");
    s.send("\r\n");
    s.send(data);
    s.done();
  });
}

