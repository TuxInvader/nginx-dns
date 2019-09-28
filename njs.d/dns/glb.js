/**

  BEGIN GLB Functions

**/

import dns from "dns.js";
export default {get_response, get_edns_subnet, process_request};

// Any encoded response packets for NGINX to send back go here 
var glb_res_packet = String.bytesFrom([]);

// Client subnet gets stored in the variable if we have one
var glb_edns_subnet = String.bytesFrom([]);

// Function for js_set to use in order to pick up the glb_res_packet above
function get_response(s) {
  return glb_res_packet;
}

// Function to get the EDNS subnet
function get_edns_subnet(s) {
  return glb_edns_subnet;
}

// Process a DNS request and generate a response packet, saving it into glb_res_packet
function process_request(s) {
  s.on("upload", function(data,flags) {
    s.warn( "Received: " + data.toString('hex') );
    var packet = dns.parse_packet(data);
    var glb_use_edns = new Boolean(parseInt(s.variables.glb_use_edns));
    s.warn( "ID: " + packet.id );
    s.warn( "QD: " + packet.qd );
    s.warn( "AR: " + packet.ar );
    if ( packet.qd == 1 ) {
      dns.parse_question(packet);
      s.warn("Name: " + packet.question.name);

      // Decode additional records, most clients will send an EDNS (OPT) to increase payload size
      // and for EDNS Client Subnet, Cookies, etc.
      if ( packet.ar > 0 ) {
        // only decode if EDNS is enabled
        s.warn( "USE EDNS: " + glb_use_edns );
        if ( glb_use_edns ) {
          dns.parse_complete(packet,1);
          if ( "edns" in packet ) {
            if ( packet.edns.opts.csubnet ) {
              s.warn( "EDNS Subnet: " + packet.edns.opts.csubnet.subnet );
              glb_edns_subnet = packet.edns.opts.csubnet.subnet;
            }
          }
        }
      }

      // Check if we're doing GLB for the given name
      var config = glb_get_config( packet, "", s );
      if ( ! Array.isArray(config) ) {
        s.warn("Failed to get config for: " + packet.question.name );
        glb_res_packet = glb_failure(packet, dns.dns_codes.NXDOMAIN );
        s.warn( "Sending: " + glb_res_packet.toString('hex') );
        s.done();
        return;
      }

      // GSLB this muther
      var nodes = glb_get_nodes( packet, config, s );
      if ( ! Array.isArray(nodes) ) {
        s.warn("Failed to get any nodes for: " + packet.question.name );
        glb_res_packet = glb_failure(packet, dns.dns_codes.SERVFAIL );
        s.warn( "Sending: " + glb_res_packet.toString('hex') );
        s.done();
        return;
      }

      // Build an array of answers from the nodes
      var answers = [];
      if ( config[1] == "active" ) {
        nodes.forEach( function(node) {
          answers.push( {name: packet.question.name, type: dns.dns_type.A, class: dns.dns_class.IN, ttl: config[2], rdata: node} );
        });
      } else if ( config[1] == "random" ) {
        var node = nodes[Math.floor(Math.random()*nodes.length)];
        answers.push( {name: packet.question.name, type: dns.dns_type.A, class: dns.dns_class.IN, ttl: config[2], rdata: node} );
      } else if ( config[1] == "geoip" ) {
        var distance=99999999;
        var closest = [];
        var client_ip, client_lat, client_lon;
        /**if ( glb_edns_subnet ) {
          client_lat = s.variables.edns_latitude;
          client_lon = s.variables.edns_longitude;
          client_ip = glb_edns_subnet;
        } else { **/
          client_lat = s.variables.geoip2_latitude;
          client_lon = s.variables.geoip2_longitude;
          client_ip = s.variables.geoip_source;
        //}
        s.warn( "Client: " + client_ip + ", Lat: " + client_lat );
        s.warn( "Client: " + client_ip + ", Lon: " + client_lon );
        for (var i=0; i< nodes.length; i++ ) {
          var suffix = "_geoip_" + nodes[i].replace(/\./g, '_');
          var node_location = glb_get_config( packet, suffix, s )
          if ( ! node_location ) {
            s.warn( "GEO location missing. Please add GEOIP key for node: " + nodes[i] );
            continue;
          }
          var nd = glb_calc_distance( client_lon, client_lat,
                                      node_location[1], node_location[0]);
          s.warn( "Distance to: " + nodes[i] + " - " + nd );
          if ( nd < distance ) {
            closest = [ nodes[i] ];
            distance = nd;
          } else if ( nd == distance ) {
            closest.push( nodes[i] );
          }
        }
        closest.forEach( function(node) {
          answers.push( {name: packet.question.name, type: dns.dns_type.A, class: dns.dns_class.IN, ttl: config[2], rdata: node} );
        });
      } else {
        s.warn("Unknown LB Algorithm: '" + config[1] + "' for: " + packet.question.name );
        glb_res_packet = glb_failure(packet, dns.dns_codes.SERVFAIL );
        s.warn( "Sending: " + glb_res_packet.toString('hex') );
        s.done();
        return;
      }

      // Shortcut - copy data from request
      glb_res_packet = dns.shortcut_response(data, packet, answers);

      // The long way, decode/encode
      //var response = dns.gen_response_packet( packet, packet.question, answers, [], [] );
      //glb_res_packet = dns.encode_packet( response );

      s.warn( "Sending: " + glb_res_packet.toString('hex') );
      s.done();
    }
  });
}

function glb_failure(packet, code) {
  var failed = dns.gen_new_packet( packet.id, packet.flags, packet.codes);
  failed.question = packet.question;
  failed.qd = 1;
  failed.codes |= code;
  failed.flags |= dns.dns_flags.QR;
  return dns.encode_packet( failed );
}
  
function glb_get_config( packet, suffix,  s) {
  var key = packet.question.name.replace(/\./g, '_') + suffix;
  var uri = '/4/stream/keyvals/glb_config';
  var config;
  if ( njs.version.slice(0,3) >= 0.9 ) {
    // future functionality
    var db = s.api( uri );
    config = db.read(key);
  } else {
    config = s.variables[ key ];
  }
  if ( config ) {
    config = config.split(',');
  }
  return config;
}

function glb_get_nodes( packet, config, s ) {
  var key = packet.question.name.replace(/\./g, '_');
  var uri = "/4/" + config[0] + "/upstreams/" + key;
  var nodes;
  if ( njs.version.slice(0,3) >= 0.9 ) {
    var db = s.api( uri );
    var json = db.read(key);
    nodes = glb_process_upstream_status( json, config );
  } else {
    // No API, so try _nodes list
    nodes = s.variables[ key + "_nodes" ];
    nodes = nodes.split(',');
  }
  return nodes;
}

function glb_process_upstream_status( json, config ) {
  // TODO process upstream peers
  var primary = [];
  var backup = [];
}

/**
 * Calculate distance between two GPS locations.
 * Thanks to: https://www.barattalo.it/coding/decimal-degrees-conversion-and-distance-of-two-points-on-google-map/
**/
function glb_calc_distance(lat1,lon1,lat2,lon2) {
    var R = 6371; // km (change this constant to get miles)
    var dLat = (lat2-lat1) * Math.PI / 180;
    var dLon = (lon2-lon1) * Math.PI / 180;
    var a = Math.sin(dLat/2) * Math.sin(dLat/2) +
        Math.cos(lat1 * Math.PI / 180 ) * Math.cos(lat2 * Math.PI / 180 ) *
        Math.sin(dLon/2) * Math.sin(dLon/2);
    var c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    var d = R * c;
    if (d>1) return Math.round(d);
    else if (d<=1) return Math.round(d*1000)+"m";
    return d;
}

