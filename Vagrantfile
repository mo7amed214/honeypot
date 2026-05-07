LEVEL3_USER = ENV.fetch("LEVEL3_USER", "john")
LEVEL3_PASSWORD = ENV.fetch("LEVEL3_PASSWORD", "Cisco")
BASE_BOX = ENV.fetch("HONEYPOT_VAGRANT_BOX", "bento/ubuntu-22.04")
EWS_MODE = ENV.fetch("HONEYPOT_EWS_MODE", "linux")
EWS_WINDOWS_BOX = ENV.fetch("HONEYPOT_EWS_BOX", "honeypot/ews-win11-local")
RAW_PROFILE = ENV.fetch("HONEYPOT_VAGRANT_PROFILE", "laptop1-safe")
PROFILE = RAW_PROFILE == "full" ? "ews-only" : RAW_PROFILE
BRIDGE_IFACE = ENV.fetch("HONEYPOT_BRIDGE_IFACE", "Realtek Gaming GbE Family Controller")
SAFE_NET_PREFIX = ENV.fetch("HONEYPOT_SAFE_NET_PREFIX", "192.168.56")
INTEGRATION_NET_PREFIX = ENV.fetch("HONEYPOT_INTEGRATION_NET_PREFIX", "172.30.70")
ENABLE_INTEGRATION_NIC = ENV.fetch("HONEYPOT_ENABLE_INTEGRATION_NIC", "0") == "1"
EWS_WINDOWS_SAFE_MEMORY = ENV.fetch("HONEYPOT_EWS_WINDOWS_SAFE_MEMORY", "4096").to_i
EWS_WINDOWS_SAFE_CPUS = ENV.fetch("HONEYPOT_EWS_WINDOWS_SAFE_CPUS", "2").to_i
EWS_WINDOWS_BRIDGE_MEMORY = ENV.fetch("HONEYPOT_EWS_WINDOWS_BRIDGE_MEMORY", "8256").to_i
EWS_WINDOWS_BRIDGE_CPUS = ENV.fetch("HONEYPOT_EWS_WINDOWS_BRIDGE_CPUS", "3").to_i
SAFE_SMB_MEMORY = ENV.fetch("HONEYPOT_SAFE_SMB_MEMORY", "1024").to_i
SAFE_SMB_CPUS = ENV.fetch("HONEYPOT_SAFE_SMB_CPUS", "1").to_i
SAFE_HISTORIAN_MEMORY = ENV.fetch("HONEYPOT_SAFE_HISTORIAN_MEMORY", "1536").to_i
SAFE_HISTORIAN_CPUS = ENV.fetch("HONEYPOT_SAFE_HISTORIAN_CPUS", "1").to_i
SAFE_OPCUA_MEMORY = ENV.fetch("HONEYPOT_SAFE_OPCUA_MEMORY", "1536").to_i
SAFE_OPCUA_CPUS = ENV.fetch("HONEYPOT_SAFE_OPCUA_CPUS", "1").to_i
SAFE_ZEEK_MEMORY = ENV.fetch("HONEYPOT_SAFE_ZEEK_MEMORY", "1536").to_i
SAFE_ZEEK_CPUS = ENV.fetch("HONEYPOT_SAFE_ZEEK_CPUS", "1").to_i
EWS_ONLY_MEMORY = ENV.fetch("HONEYPOT_EWS_ONLY_MEMORY", "2048").to_i
EWS_ONLY_CPUS = ENV.fetch("HONEYPOT_EWS_ONLY_CPUS", "2").to_i

if EWS_MODE == "windows" && EWS_WINDOWS_BOX.strip.empty?
  raise "Register a Windows 11 box first, then set HONEYPOT_EWS_BOX or use the default honeypot/ews-win11-local"
end

PROFILE_MACHINES = {
  "laptop1-safe" => {
    description: "Laptop1 roles and IPs on a safe host-only network.",
    network: :private,
    machines: {
      "ews" => {
        hostname: "EWS-WIN11",
        vm_name: "EWS-WIN11-bridge",
        ip: "#{SAFE_NET_PREFIX}.5",
        memory: EWS_MODE == "windows" ? EWS_WINDOWS_SAFE_MEMORY : 4096,
        cpus: EWS_MODE == "windows" ? EWS_WINDOWS_SAFE_CPUS : 3,
        role: "ews",
        promisc_policy: "allow-all",
        nic_type: "82540EM",
      },
      "smb" => {
        hostname: "smb",
        vm_name: "smb-bridge",
        ip: "#{SAFE_NET_PREFIX}.7",
        memory: SAFE_SMB_MEMORY,
        cpus: SAFE_SMB_CPUS,
        role: "smb",
        promisc_policy: "allow-all",
        nic_type: "82540EM",
      },
      "historian" => {
        hostname: "historian",
        vm_name: "Historian-bridge",
        ip: "#{SAFE_NET_PREFIX}.10",
        memory: SAFE_HISTORIAN_MEMORY,
        cpus: SAFE_HISTORIAN_CPUS,
        role: "historian",
        promisc_policy: "allow-all",
        nic_type: "82540EM",
      },
      "opcua" => {
        hostname: "opcuaserver",
        vm_name: "opuca-vm-bridge",
        ip: "#{SAFE_NET_PREFIX}.11",
        memory: SAFE_OPCUA_MEMORY,
        cpus: SAFE_OPCUA_CPUS,
        role: "opcua",
        promisc_policy: "allow-network",
        nic_type: "82540EM",
      },
      "zeek" => {
        hostname: "zeek",
        vm_name: "Zeek-bridge",
        ip: "#{SAFE_NET_PREFIX}.13",
        memory: SAFE_ZEEK_MEMORY,
        cpus: SAFE_ZEEK_CPUS,
        role: "zeek",
        promisc_policy: "allow-all",
        nic_type: "82540EM",
      },
    },
  },
  "laptop1-bridge" => {
    description: "Near-live bridged layout matching laptop1's LAN-facing NICs.",
    network: :public,
    machines: {
      "ews" => {
        hostname: "EWS-WIN11",
        vm_name: "EWS-WIN11-bridge",
        ip: "192.168.1.5",
        memory: EWS_MODE == "windows" ? EWS_WINDOWS_BRIDGE_MEMORY : 4096,
        cpus: EWS_MODE == "windows" ? EWS_WINDOWS_BRIDGE_CPUS : 3,
        role: "ews",
        promisc_policy: "allow-all",
        nic_type: "82540EM",
      },
      "smb" => {
        hostname: "smb",
        vm_name: "smb-bridge",
        ip: "192.168.1.7",
        memory: 2048,
        cpus: 1,
        role: "smb",
        promisc_policy: "allow-all",
        nic_type: "82540EM",
      },
      "historian" => {
        hostname: "historian",
        vm_name: "Historian-bridge",
        ip: "192.168.1.10",
        memory: 2048,
        cpus: 1,
        role: "historian",
        promisc_policy: "allow-all",
        nic_type: "82540EM",
      },
      "opcua" => {
        hostname: "opcuaserver",
        vm_name: "opuca-vm-bridge",
        ip: "192.168.1.11",
        memory: 2496,
        cpus: 2,
        role: "opcua",
        promisc_policy: "allow-network",
        nic_type: "82540EM",
      },
      "zeek" => {
        hostname: "zeek",
        vm_name: "Zeek-bridge",
        ip: "192.168.1.13",
        memory: 2048,
        cpus: 2,
        role: "zeek",
        promisc_policy: "allow-all",
        nic_type: "82540EM",
      },
    },
  },
  "ews-only" => {
    description: "Single EWS VM running all other Level 3 services as Docker containers.",
    network: :private,
    machines: {
      "ews" => {
        hostname: "EWS-WIN11",
        vm_name: "EWS-containers",
        ip: "#{SAFE_NET_PREFIX}.5",
        memory: EWS_MODE == "windows" ? EWS_WINDOWS_SAFE_MEMORY : EWS_ONLY_MEMORY,
        cpus: EWS_MODE == "windows" ? EWS_WINDOWS_SAFE_CPUS : EWS_ONLY_CPUS,
        role: "ews",
        promisc_policy: "allow-all",
        nic_type: "82540EM",
      },
    },
  },
  "integration" => {
    description: "Clean integration-only surface on 172.30.70.0/24.",
    network: :private,
    machines: {
      "ews" => {
        hostname: "level3-ews",
        vm_name: "honeypot-ews-integration",
        ip: "172.30.70.10",
        memory: EWS_MODE == "windows" ? 4096 : 2048,
        cpus: 2,
        role: "ews",
        promisc_policy: "deny",
        nic_type: "82540EM",
      },
      "historian" => {
        hostname: "level3-historian",
        vm_name: "honeypot-historian-integration",
        ip: "172.30.70.11",
        memory: 3072,
        cpus: 2,
        role: "historian",
        promisc_policy: "deny",
        nic_type: "82540EM",
      },
      "opcua" => {
        hostname: "level3-opcua",
        vm_name: "honeypot-opcua-integration",
        ip: "172.30.70.12",
        memory: 2048,
        cpus: 2,
        role: "opcua",
        promisc_policy: "deny",
        nic_type: "82540EM",
      },
      "zeek" => {
        hostname: "level3-zeek",
        vm_name: "honeypot-zeek-integration",
        ip: "172.30.70.13",
        memory: 4096,
        cpus: 2,
        role: "zeek",
        promisc_policy: "allow-all",
        nic_type: "82540EM",
      },
      "smb" => {
        hostname: "level3-smb",
        vm_name: "honeypot-smb-integration",
        ip: "172.30.70.14",
        memory: 2048,
        cpus: 2,
        role: "smb",
        promisc_policy: "deny",
        nic_type: "82540EM",
      },
    },
  },
}.freeze

unless PROFILE_MACHINES.key?(PROFILE)
  raise "Unknown HONEYPOT_VAGRANT_PROFILE=#{RAW_PROFILE}. Expected one of: #{(PROFILE_MACHINES.keys + ['full']).join(', ')}"
end

INTEGRATION_IP_SUFFIX = {
  "ews" => 10,
  "historian" => 11,
  "opcua" => 12,
  "zeek" => 13,
  "smb" => 14,
}.freeze

profile_spec = PROFILE_MACHINES.fetch(PROFILE)
machines = profile_spec.fetch(:machines)

Vagrant.configure("2") do |config|
  config.vm.box = BASE_BOX
  config.ssh.insert_key = false

  machines.each do |name, spec|
    config.vm.define name do |node|
      node.vm.hostname = spec[:hostname]

      if PROFILE == "integration"
        node.vm.network "private_network",
          ip: spec[:ip],
          virtualbox__intnet: "l3_ops_net"
      elsif profile_spec[:network] == :public
        node.vm.network "public_network", bridge: BRIDGE_IFACE, ip: spec[:ip]
      else
        node.vm.network "private_network", ip: spec[:ip]
      end

      if PROFILE != "integration" && ENABLE_INTEGRATION_NIC
        integration_suffix = INTEGRATION_IP_SUFFIX.fetch(name)
        node.vm.network "private_network",
          ip: "#{INTEGRATION_NET_PREFIX}.#{integration_suffix}",
          virtualbox__intnet: "l3_ops_net"
      end

      if name == "ews" && EWS_MODE == "windows"
        node.vm.box = EWS_WINDOWS_BOX
        node.vm.communicator = "winrm"
        node.winrm.username = ENV.fetch("HONEYPOT_EWS_WINRM_USER", "vagrant")
        node.winrm.password = ENV.fetch("HONEYPOT_EWS_WINRM_PASSWORD", "vagrant")
        node.vm.guest = :windows
        node.vm.synced_folder ".", "C:/vagrant/honeypot"
      else
        node.vm.synced_folder ".", "/opt/honeypot"
      end

      node.vm.provider "virtualbox" do |vb|
        vb.name = spec[:vm_name]
        vb.memory = spec[:memory]
        vb.cpus = spec[:cpus]
        vb.linked_clone = true if vb.respond_to?(:linked_clone=)
        if name == "ews" && EWS_MODE == "windows"
          vb.customize ["modifyvm", :id, "--macaddress1", "auto"]
          vb.customize ["modifyvm", :id, "--macaddress2", "auto"]
          if PROFILE != "integration" && ENABLE_INTEGRATION_NIC
            vb.customize ["modifyvm", :id, "--macaddress3", "auto"]
          end
        end
        vb.customize ["modifyvm", :id, "--nictype2", spec[:nic_type]]
        vb.customize ["modifyvm", :id, "--nicpromisc2", spec[:promisc_policy]]
        if PROFILE != "integration" && ENABLE_INTEGRATION_NIC
          vb.customize ["modifyvm", :id, "--nictype3", "82540EM"]
        end
      end

      if name == "ews" && EWS_MODE == "windows"
        integration_ip = if PROFILE != "integration" && ENABLE_INTEGRATION_NIC
          "#{INTEGRATION_NET_PREFIX}.#{INTEGRATION_IP_SUFFIX.fetch(name)}"
        elsif PROFILE == "integration"
          spec[:ip]
        else
          ""
        end

        node.vm.provision "shell",
          path: "vagrant/provision/ews_windows.ps1",
          env: {
            "HONEYPOT_PROFILE" => PROFILE,
            "HONEYPOT_ENABLE_INTEGRATION_NIC" => ENABLE_INTEGRATION_NIC ? "1" : "0",
            "HONEYPOT_EWS_SERVICE_IP" => spec[:ip],
            "HONEYPOT_EWS_INTEGRATION_IP" => integration_ip,
          },
          args: [LEVEL3_USER, LEVEL3_PASSWORD],
          privileged: true
      elsif name == "ews" && PROFILE == "ews-only" && EWS_MODE != "windows"
        node.vm.provision "shell", path: "vagrant/provision/common.sh", args: [LEVEL3_USER]
        node.vm.provision "shell",
          env: {
            "LEVEL3_PASSWORD" => LEVEL3_PASSWORD,
            "HONEYPOT_ENABLE_INTEGRATION_NIC" => ENABLE_INTEGRATION_NIC ? "1" : "0",
            "HONEYPOT_INTEGRATION_IP" => ENABLE_INTEGRATION_NIC ? "#{INTEGRATION_NET_PREFIX}.#{INTEGRATION_IP_SUFFIX.fetch('ews')}" : "",
            "HONEYPOT_OT_CORE_L3_IP" => ENV.fetch("HONEYPOT_OT_CORE_L3_IP", "172.30.70.1"),
            "HONEYPOT_DECOY_SUBNET" => ENV.fetch("HONEYPOT_DECOY_SUBNET", "172.30.40.0/24"),
          },
          path: "vagrant/provision/ews_with_containers.sh",
          args: [LEVEL3_USER]
      elsif name == "ews" && PROFILE == "integration" && EWS_MODE != "windows"
        node.vm.provision "shell",
          env: {
            "LEVEL3_PASSWORD" => LEVEL3_PASSWORD,
            "HONEYPOT_EWS_SERVICE_IP" => spec[:ip],
            "HONEYPOT_OT_CORE_L3_IP" => ENV.fetch("HONEYPOT_OT_CORE_L3_IP", "172.30.70.1"),
            "HONEYPOT_DECOY_SUBNET" => ENV.fetch("HONEYPOT_DECOY_SUBNET", "172.30.40.0/24"),
          },
          path: "vagrant/provision/ews_ingress_minimal.sh",
          args: [LEVEL3_USER]
      else
        node.vm.provision "shell", path: "vagrant/provision/common.sh", args: [LEVEL3_USER]
        node.vm.provision "shell", env: { "LEVEL3_PASSWORD" => LEVEL3_PASSWORD }, path: "vagrant/provision/#{spec[:role]}.sh"
      end
    end
  end
end
