
import glb from './dns/glb.js';
import dns from './dns/dns.js';

/**
 *  GLB Functions
**/

// GLB return the response packet to js_set
function glb_get_response(s) {
  return glb.get_response(s);
}

// GLB setup the on(upload) callback to process DNS packets
function glb_process_request(s) {
  return glb.process_request(s);
}

// GLB return the EDNS subnet to the js_set call for GEOIP2
function glb_get_edns_subnet(s) {
  return glb.get_edns_subnet(s);
}

/**
 *  DNS Functions
**/

// DNS over HTTPS gateway - use as js_filter
function dns_filter_doh_request(s) {
  return dns.filter_doh_request(s);
}

function dns_preread_doh_request(s) {
  return dns.preread_doh_request(s);
}

function dns_preread_udp_request(s) {
  return dns.preread_udp_request(s);
}

function dns_preread_tcp_request(s) {
  return dns.preread_tcp_request(s);
}

// Return the DNS Question
function dns_get_qname(s) {
  return dns.get_qname(s);
}

// return the DNS Response, if we want to override (block) the domain
function dns_get_response(s) {
  return dns.get_response(s);
}

//function dns_filter_udp_request(s) {
//  return dns.filter_udp_request(s);
//}

