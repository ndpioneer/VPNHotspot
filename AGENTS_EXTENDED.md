# Routed IPv6, IPv4-Disabled Hotspot Architecture & Enhancements

## Overview
This repository has been extended beyond the original userspace NAT66 mode to support:
1. **Pure Routed IPv6 Subnet Forwarding (No NAT):** WireGuard /64 delegated prefix routing with SLAAC RDNSS, kernel-level TCP MSS clamping, and active carrier-leakage blocking.
2. **IPv6-Only Operation (Disable IPv4):** Total suppression of IPv4 forwarding, ARP/DHCP wait loops, and IPv4 iptables setup, designed for native IPv6 + NAT64 deployments.
3. **Privacy & Freedom Focus:** Complete removal of Google Firebase Analytics, Crashlytics telemetry, and proprietary reporting dependencies.
4. **Resilient UI State & Reachability Tracking:** Auto-refreshing interface states and neighbor reachability aligned with link-local status.

---

## 1. Protobuf IPC (`mobile/src/main/proto/daemon.proto`)
The `SessionConfig` protobuf message includes:
- `bool disable_ipv4 = 13`: When `true`, instructs the daemon and routing subsystems to bypass all IPv4 operations.
- `optional Ipv6Prefix routed_ipv6_prefix = 14`: The delegated `/64` prefix discovered from the upstream tunnel.
- `optional bytes routed_ipv6_dns = 15`: The IPv6 DNS server (RDNSS) discovered from upstream LinkProperties (or fallback to Cloudflare `2606:4700:4700::1111`).

---

## 2. Shared Models & Wire Formats (`mobile/src/main/rust/vpnhotspotd/src/shared/`)
- `model.rs`:
  - `SessionConfig` struct includes `disable_ipv4: bool`, `routed_ipv6_prefix: Option<Ipv6Cidr>`, and `routed_ipv6_dns: Option<Ipv6Addr>`.
- `protocol.rs`:
  - `read_session_config`: Deserializes the three protobuf fields into the Rust `SessionConfig`.
- `ra_wire.rs`:
  - `make_current_ra_packet(advertised_prefix: Ipv6Cidr, dns_server: Ipv6Addr, mtu: u32)`:
    Emits RFC 4861 Router Advertisements with Prefix Information (autonomous=true, on-link=true, valid=3600, preferred=1800) and RFC 8106 RDNSS options (lifetime=600).

---

## 3. Daemon Routing & Policy Rules (`mobile/src/main/rust/vpnhotspotd/src/routing/desired.rs`)
When `config.routed_ipv6_prefix` is present:
1. **Address Assignment:** Assigns `<prefix>::1/64` to `config.downstream` via Netlink `IpAddressCommand`.
2. **Policy Routing:** Installs `ip -6 rule` at priority `20700` (`RULE_PRIORITY_UPSTREAM_BASE`):
   - `iif <downstream> lookup 1000 + ifindex` (pointing directly to WireGuard `tun0`'s routing table).
3. **TCP MSS Clamping:**
   - Adds an `ip6tables` rule in `mangle` `FORWARD`:
     `-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`
   - Clamps client MSS to the tunnel PMTU, preventing Path MTU blackholes and dropped TLS handshakes over encapsulated links.
4. **Carrier RA Suppression:**
   - Adds an `ip6tables` rule in `OUTPUT` on `filter`:
     `-o <downstream> -p icmpv6 --icmpv6-type router-advertisement -m mark ! --mark 0x00030063/0x0003ffff -j DROP`
   - Blocks Android's system `RouterAdvertisementDaemon` from broadcasting carrier-delegated cellular IPv6 prefixes onto the downstream Wi-Fi interface.
5. **Firewall Forwarding:** Ensures `vpnhotspot_forward` chain in `filter` table allows bidirectional IPv6 forwarding matching `<prefix>` without any MASQUERADE or NAT.
6. **Active IPv4 Suppression & DHCPv4 Blocking:** When `config.disable_ipv4 == true`:
   - Bypasses all normal IPv4 routing chains, policy rules, and client forwarding.
   - Installs active packet drop rules in `raw` (`PREROUTING`) and `filter` (`INPUT`, `OUTPUT`) for UDP port 67, preventing Android's system DHCP server from leasing IPv4 addresses to downstream clients.
   - Installs active drop rules in `raw` and `filter` across `INPUT`, `FORWARD`, and `OUTPUT` on the downstream interface to completely suppress all downstream IPv4 traffic.

---

## 4. Router Advertisement Engine (`mobile/src/main/rust/vpnhotspotd/src/nat66/`)
- `ra.rs`:
  - Loop condition supports `current.routed_ipv6_prefix.is_some()`.
  - Does NOT wait for `current.clients.is_empty()` in routed mode; begins advertising immediately on startup so new clients can discover the network upon association.
  - Active carrier suppression: Automatically detects any foreign IPv6 prefixes on downstream via Netlink and broadcasts zero-lifetime deprecation RAs (`send_zero_lifetime_ra`).
  - Dynamic MTU Clamping:
    `mtu = min(downstream_mtu, upstream_wireguard_mtu)`. Guarantees client MSS/PMTU aligns with WireGuard encapsulation without packet drops.
- `nat66/mod.rs`:
  - In Routed mode, only `ra::spawn_loop` runs. Userspace TPROXY listeners and NFQUEUE ICMP echo proxies are bypassed (standard kernel forwarding handles traffic directly).

---

## 5. Session Lifecycle (`mobile/src/main/rust/vpnhotspotd/src/session.rs`)
- `Session::start`:
  - When `config.disable_ipv4 == true`, skips `downstream::wait_ipv4` so the session does not hang waiting for an IPv4 lease or address.
- `Session::replace_config`:
  - Keeps the RA engine alive when `config.routed_ipv6_prefix.is_some()`, preventing teardown when `ipv6_nat` is None.

---

## 6. Traffic Monitoring (`mobile/src/main/rust/vpnhotspotd/src/traffic.rs`)
- `read_counters`:
  - When `disable_ipv4 == true` or `client_macs.is_empty()`, returns an empty list without invoking `/system/bin/iptables-restore` on non-existent IPv4 chains (`vpnhotspot_stats`), avoiding `exit status: 1 line 2 failed` errors.

---

## 7. Kotlin Layer & UI Refinements (`mobile/src/main/java/be/mygod/vpnhotspot/`)
- `Routing.kt`:
  - `Ipv6Mode.Routed` added to `enum class Ipv6Mode`.
  - `nextConfig()`: Auto-discovers the `/64` prefix from `primaryUpstream.upstream?.properties?.linkAddresses` (non-link-local `/64`) and DNS from `dnsServers` (IPv6, fallback to Cloudflare `2606:4700:4700::1111`).
- `SettingsScreen.kt`:
  - Exposes `Disable IPv4` switch and `Routed (/64)` option in the IPv6 Mode selector.
  - Dynamically hides `IPv4 masquerade mode` when `Disable IPv4` is active.
- `ClientsScreen.kt`:
  - Binds client global IPv6 reachability status to the link-local (`fe80::`) neighbor state to prevent stale "reachable" indicators after client disconnect.
- `TetheringScreen.kt`:
  - Added a lifecycle-aware 5-second auto-refresh polling loop while resumed, automatically detecting and displaying the assigned `/64` prefix.
- `App.kt` & Telemetry:
  - Completely excised Firebase Analytics, FirebaseCrashlytics, and Google Services plugins.
  - Release APKs auto-signed with debug keystore.
