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
    critical_reason: string &log;
    source_role: string &log;
    session_duration: interval &log;
    orig_bytes: count &log;
    resp_bytes: count &log;
  };

  # Heuristic byte markers for OPC UA Write-like service IDs in binary payloads.
  #
  # Avoid markers containing NUL bytes here: Zeek logs reporter errors for
  # embedded-NUL string constants even though the script still loads.
  const write_marker_nodeid_02a1: string = "\x01\xa1\x02" &redef;

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
global pending_detections: table[string] of Info = table();

function detect_marker(payload: string): string
  {
  if ( write_marker_nodeid_02a1 in payload )
    return "nodeid_02a1_prefix";

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
  local marker = detect_marker(payload);
  if ( marker == "" )
    marker = "msgf_only";

  local matched_tag = contains_critical_tag(payload);
  local critical_target = "false";
  local confidence = "medium";
  local critical_reason = "write_like_payload";
  if ( marker != "msgf_only" )
    confidence = "high";
  if ( matched_tag != "" )
    {
    critical_target = "true";
    confidence = "high";
    critical_reason = "critical_tag_keyword";
    }

  add seen_uids[c$uid];
  local source_role = "other_local";
  if ( c$id$orig_h == 192.168.1.5 )
    source_role = "ews";
  else if ( c$id$orig_h == 192.168.1.9 )
    source_role = "monitor";

  pending_detections[c$uid] =
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
     $confidence=confidence,
     $critical_reason=critical_reason,
     $source_role=source_role,
     $session_duration=0secs,
     $orig_bytes=0,
     $resp_bytes=0];
  }

event connection_state_remove(c: connection)
  {
  if ( c$uid !in pending_detections )
    return;

  local info = pending_detections[c$uid];
  info$session_duration = c$duration;
  info$orig_bytes = c$orig$size;
  info$resp_bytes = c$resp$size;

  if ( info$critical_target != "true" &&
       c$id$orig_h == 192.168.1.5 &&
       c$duration >= 5secs &&
       c$orig$size >= 4096 )
    {
    info$critical_target = "true";
    info$confidence = "high";
    info$critical_reason = "ews_sustained_write_session";
    }

  Log::write(LOG, info);
  delete pending_detections[c$uid];
  }
