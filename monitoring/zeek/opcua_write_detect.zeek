module OPCUAWriteDetect;

export {
  redef enum Log::ID += { LOG };

  type Info: record {
    ts: time &log;
    uid: string &log;
    id_orig_h: addr &log;
    id_orig_p: port &log;
    id_resp_h: addr &log;
    id_resp_p: port &log;
    detection_id: string &log;
    service: string &log;
    marker: string &log;
    matched_tag: string &log;
    critical_target: string &log;
    confidence: string &log;
  };

  # Heuristic byte markers for OPC UA Write-like service IDs in binary payloads.
  const write_markers: vector of string = {
    "\x01\xa1\x02",     # two-byte numeric node id encoding marker + 0x02A1
    "\xa1\x02\x00\x00",# little-endian 0x000002A1
    "\xcd\x02\x00\x00" # alternative observed write-like marker in some stacks
  } &redef;

  # Potentially safety/quality-impacting tag names expected from this environment.
  const critical_tag_keywords: vector of string = {
    "air_pressure_bar",
    "weld_cell_temperature_c",
    "pkg_seal_temp_c",
    "cooling_water_temp_c",
    "line1_vibration_mm_s"
  } &redef;
}

global seen_uids: set[string] = set();

function contains_marker(payload: string): string
  {
  for ( i in write_markers )
    {
    if ( write_markers[i] in payload )
      return write_markers[i];
    }

  return "";
  }

function contains_critical_tag(payload: string): string
  {
  for ( i in critical_tag_keywords )
    {
    if ( critical_tag_keywords[i] in payload )
      return critical_tag_keywords[i];
    }

  return "";
  }

event zeek_init()
  {
  Log::create_stream(LOG, [$columns=Info, $path="opcua_write"]);
  }

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
  {
  if ( ! is_orig )
    return;

  if ( c$id$resp_p != 4840/tcp )
    return;

  if ( c$uid in seen_uids )
    return;

  if ( |payload| == 0 )
    return;

  # Most client request chunks are MSGF; combine with write marker to reduce noise.
  if ( /MSGF/ !in payload )
    return;

  # Marker bytes vary between stacks and framing details. Treat MSGF client
  # request packets on OPC UA port 4840 as write-like candidates, then boost
  # confidence when known write markers are present.
  local marker = contains_marker(payload);
  if ( marker == "" )
    marker = "msgf_only";

  local matched_tag = contains_critical_tag(payload);
  local critical_target = "false";
  local confidence = "medium";
  if ( marker != "msgf_only" )
    confidence = "high";
  if ( matched_tag != "" )
    {
    critical_target = "true";
    confidence = "high";
    }

  add seen_uids[c$uid];

  Log::write(LOG,
    [$ts=network_time(),
     $uid=c$uid,
     $id_orig_h=c$id$orig_h,
     $id_orig_p=c$id$orig_p,
     $id_resp_h=c$id$resp_h,
     $id_resp_p=c$id$resp_p,
      $detection_id="100304A",
     $service="opcua.write_like",
        $marker=marker,
        $matched_tag=matched_tag,
        $critical_target=critical_target,
        $confidence=confidence]);
  }
