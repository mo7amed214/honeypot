module DiscoveryScanDetect;

export {
  redef enum Log::ID += { LOG };

  type Info: record {
    ts: time &log;
    src_h: addr &log;
    detection_id: string &log;
    service: string &log;
    unique_targets: count &log;
    unique_ports: count &log;
    unique_pairs: count &log;
    confidence: string &log;
  };

  const watched_ports: set[port] = {
    22/tcp,
    80/tcp,
    139/tcp,
    443/tcp,
    445/tcp,
    3389/tcp,
    3000/tcp,
    4840/tcp,
    5000/tcp
  } &redef;

  const min_unique_targets: count = 3 &redef;
  const min_unique_ports: count = 5 &redef;
  const min_unique_pairs: count = 10 &redef;
}

type ScanState: record {
  targets: set[addr];
  ports: set[port];
  pairs: set[string];
  alerted: bool;
};

global scan_state: table[addr] of ScanState &write_expire=30secs;

event zeek_init()
  {
  Log::create_stream(LOG, [$columns=Info, $path="discovery_scan"]);
  }

event connection_state_remove(c: connection)
  {
  if ( c$id$resp_p !in watched_ports )
    return;

  if ( c$id$orig_h !in Site::local_nets || c$id$resp_h !in Site::local_nets )
    return;

  if ( c$id$orig_h == c$id$resp_h )
    return;

  local src = c$id$orig_h;
  if ( src !in scan_state )
    {
    local empty_targets: set[addr] = set();
    local empty_ports: set[port] = set();
    local empty_pairs: set[string] = set();
    scan_state[src] = [$targets=empty_targets, $ports=empty_ports, $pairs=empty_pairs, $alerted=F];
    }

  add scan_state[src]$targets[c$id$resp_h];
  add scan_state[src]$ports[c$id$resp_p];
  add scan_state[src]$pairs[fmt("%s:%s", c$id$resp_h, c$id$resp_p)];

  local target_count = |scan_state[src]$targets|;
  local port_count = |scan_state[src]$ports|;
  local pair_count = |scan_state[src]$pairs|;

  if ( scan_state[src]$alerted )
    return;

  if ( target_count < min_unique_targets || port_count < min_unique_ports || pair_count < min_unique_pairs )
    return;

  scan_state[src]$alerted = T;

  local confidence = "medium";
  if ( pair_count >= 18 || (target_count >= 4 && port_count >= 6) )
    confidence = "high";

  Log::write(LOG,
    [$ts=network_time(),
     $src_h=src,
     $detection_id="100307A",
     $service="network.discovery_scan",
     $unique_targets=target_count,
     $unique_ports=port_count,
     $unique_pairs=pair_count,
     $confidence=confidence]);
  }
