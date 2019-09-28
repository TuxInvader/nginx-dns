
import glb from './dns/glb.js';
import doh from './dns/doh.js';

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

// DNS over HTTPS gateway - use as js_filter
function doh_filter_request(s) {
  return doh.filter_request(s);
}

// Return the DNS Question
function doh_get_dns_name(s) {
  return doh.get_dns_name(s);
}
