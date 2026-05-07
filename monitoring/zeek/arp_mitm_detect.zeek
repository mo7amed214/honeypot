module ARPMitmDetect;

export {
  redef enum Log::ID += { LOG };

  type Info: record {
    ts:            time   &log;
    orig_ip:       addr   &log;
    detection_id:  string &log;
    service:       string &log;
    prev_mac:      string &log;
    new_mac:       string &log;
    confidence:    string &log;
  };

  # Only watch IPs that belong to known Level-3 assets; suppresses noise
  # from DHCP or VM provisioning events on unrelated hosts.
  const watched_ips: set[addr] = {
    192.168.1.5,   # EWS-WIN11
    192.168.1.7,   # SMB
    192.168.1.10,  # Historian
    192.168.1.11,  # OPC-UA server
    192.168.1.9,   # monitoring laptop
  } &redef;
}

# IP -> MAC mapping built from observed ARP traffic.
global ip_mac_table: table[addr] of string;

event zeek_init()
  {
  Log::create_stream(LOG, [$columns=Info, $path="arp_mitm"]);
  }

function check_arp(spa: addr, sha: string)
  {
  if ( spa !in watched_ips )
    return;

  if ( spa !in ip_mac_table )
    {
    ip_mac_table[spa] = sha;
    return;
    }

  if ( ip_mac_table[spa] == sha )
    return;

  # MAC changed for a known watched IP — ARP cache poisoning signal (T0830).
  Log::write(LOG,
    [$ts           = network_time(),
     $orig_ip      = spa,
     $detection_id = "100308A",
     $service      = "network.arp_mitm",
     $prev_mac     = ip_mac_table[spa],
     $new_mac      = sha,
     $confidence   = "high"]);

  ip_mac_table[spa] = sha;
  }

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
  {
  check_arp(SPA, SHA);
  }

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
  {
  check_arp(SPA, SHA);
  }
