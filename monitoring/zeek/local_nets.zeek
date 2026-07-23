# discovery_scan_detect.zeek gates every check on Site::local_nets, but
# nothing in this deployment ever configured it (no networks.cfg, no other
# redef anywhere in the repo) - it's empty by default, so that gate always
# returns true and the detector can never fire, on any traffic, ever.
# ot-net's subnet is pinned in docker-compose.level3.yml specifically so
# this can be a static, reliable redef rather than a guess.
redef Site::local_nets += { 172.29.88.0/24 };
