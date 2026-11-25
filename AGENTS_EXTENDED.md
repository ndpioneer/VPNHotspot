# Routed IPv6, IPv4-Disabled Hotspot Architecture & Enhancements

## Overview
This repository has been extended beyond the original userspace NAT66 mode to support:
1. **Pure Routed IPv6 Subnet Forwarding (No NAT):** WireGuard /64 delegated prefix routing with SLAAC RDNSS, kernel-level TCP MSS clamping, active carrier-leakage blocking, and automatic downstream carrier address purging.
2. **Intelligent On-Device Collision Avoidance:** Auto mode detects if the upstream tunnel interface owns host address `::1` (e.g. `::1/128`), and automatically assigns `::2/64` downstream to prevent local route collisions.
3. **Manual Subnet Override:** Supports explicit custom `/64` CIDRs with user-defined host bits while preserving auto-detection fallback.
4. **IPv6-Only Operation (Disable IPv4):** Total suppression of IPv4 forwarding, ARP/DHCP wait loops, netfilter DHCP server drops (UDP 67/68), and IPv4 iptables setup, designed for native IPv6 + NAT64 deployments.
5. **Dual-Stack TCP MSS Clamping:** Kernel-level MSS clamping to PMTU for both IPv4 and routed IPv6 to eliminate encapsulation blackholes.
6. **Privacy & Freedom Focus:** Complete removal of Google Firebase Analytics, Crashlytics telemetry, and proprietary reporting dependencies.
7. **Reactive, Event-Driven UI:** Instant UI interface address updates bound directly to `Routing.routingVersion` and `Upstreams.primary`, eliminating brute-force background polling loops.

---

## 1. Protobuf IPC (`mobile/src/main/proto/daemon.proto`)
The `SessionConfig` protobuf message includes:
- `bool disable_ipv4 = 13`: When `true`, instructs the daemon and routing subsystems to bypass all IPv4 operations.
- `optional Ipv6Prefix routed_ipv6_prefix = 14`: The delegated `/64` prefix (including host bits) discovered from the upstream tunnel or provided manually.
- `optional bytes routed_ipv6_dns = 15`: The IPv6 DNS server (RDNSS) discovered from upstream LinkProperties (or fallback to Cloudflare `2606:4700:4700::1111`).

---

## 2. Shared Models & Wire Formats (`mobile/src/main/rust/vpnhotspotd/src/shared/`)
- `model.rs`:
  - `SessionConfig` struct includes `disable_ipv4: bool`, `routed_ipv6_prefix: Option<Ipv6Inet>`, and `routed_ipv6_dns: Option<Ipv6Addr>`. Uses `Ipv6Inet` to preserve user/system host bits across the IPC boundary.
- `protocol.rs`:
  - `read_ipv6_inet`: Deserializes the protobuf prefix into an `Ipv6Inet` without zeroing host bits.
- `ra_wire.rs`:
  - `make_current_ra_packet(advertised_prefix: Ipv6Cidr, dns_server: Ipv6Addr, mtu: u32)`:
    Emits RFC 4861 Router Advertisements with Prefix Information (`autonomous=true`, `on-link=true`, `valid=3600`, `preferred=1800`) and RFC 8106 RDNSS options (`lifetime=600`).

---

## 3. Daemon Routing & Policy Rules (`mobile/src/main/rust/vpnhotspotd/src/routing/desired.rs`)
When `config.routed_ipv6_prefix` is present:
1. **Address Assignment:** Assigns `routed_prefix.address()` (e.g. `<prefix>::2/64` or custom manual host address) to `config.downstream` via Netlink `IpAddressCommand`.
2. **Policy Routing:** Installs `ip -6 rule` at priority `20700` (`RULE_PRIORITY_UPSTREAM_BASE`):
   - `iif <downstream> lookup 1000 + ifindex` (pointing directly to WireGuard `tun0`'s routing table).
3. **Dual-Stack TCP MSS Clamping:**
   - Adds `iptables` and `ip6tables` rules in `mangle` `FORWARD`:
     `-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`
   - Clamps client MSS to the tunnel PMTU for both IPv4 and IPv6, preventing Path MTU blackholes and dropped TLS handshakes over encapsulated links.
4. **Carrier RA Suppression:**
   - Adds an `ip6tables` rule in `OUTPUT` on `filter`:
     `-o <downstream> -p icmpv6 --icmpv6-type router-advertisement -m mark ! --mark 0x00030063/0x0003ffff -j DROP`
   - Blocks Android's system `RouterAdvertisementDaemon` from broadcasting carrier-delegated cellular IPv6 prefixes onto the downstream Wi-Fi interface.
5. **Firewall Forwarding:** Ensures `vpnhotspot_forward` chain in `filter` table allows bidirectional IPv6 forwarding matching `routed_prefix.network()` without any MASQUERADE or NAT.
6. **Active IPv4 Suppression & DHCPv4 Blocking:** When `config.disable_ipv4 == true`:
   - Bypasses all normal IPv4 routing chains, policy rules, and client forwarding.
   - Installs active packet drop rules in `raw` (`PREROUTING`) and `filter` (`INPUT`, `OUTPUT`) for incoming and outgoing UDP ports 67 and 68, preventing Android's system DHCP server from leasing IPv4 addresses to downstream clients.
   - Installs active drop rules in `raw` and `filter` across `INPUT`, `FORWARD`, and `OUTPUT` on the downstream interface to completely suppress all downstream IPv4 traffic.

---

## 4. Router Advertisement Engine (`mobile/src/main/rust/vpnhotspotd/src/nat66/`)
- `ra.rs`:
  - Loop condition supports `current.routed_ipv6_prefix.is_some()`.
  - Does NOT wait for `current.clients.is_empty()` in routed mode; begins advertising immediately on startup so new clients can discover the network upon association.
  - **Active Carrier Purge & Suppression:** Automatically detects foreign carrier IPv6 prefixes on downstream via Netlink, broadcasts zero-lifetime deprecation RAs (`send_zero_lifetime_ra`), and actively purges the foreign carrier IPv6 addresses from the interface via Netlink `delete_address`.
  - **Dynamic MTU Clamping:**
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
  - Collision Avoidance & Prefix Resolution: Auto mode detects if upstream owns `::1` and assigns `::2/64` to downstream Wi-Fi. Manual mode supports custom prefix entry while respecting user-specified host bits.
  - Exposes `Routing.routingVersion` `StateFlow` to notify UI observers whenever routing starts, stops, or re-configures.
- `SettingsScreen.kt`:
  - Exposes `Disable IPv4` switch and `Routed (/64)` option in the IPv6 Mode selector.
  - Dedicated `PrefixPreferenceRow` dialog with instant CIDR validation and informative placeholder text.
  - Dynamically hides `IPv4 masquerade mode` when `Disable IPv4` is active.
  - Uses updated icons: `ic_visibility_off` for Disable IPv4 and `ic_router` for Routed IPv6 Prefix.
- `ClientsScreen.kt`:
  - Binds client global IPv6 reachability status to the link-local (`fe80::`) neighbor state to prevent stale "reachable" indicators after client disconnect.
- `TetheringScreen.kt`:
  - Reactive interface lookup hooked into `Routing.routingVersion` and `Upstreams.primary`.
  - Delayed refresh handles Linux kernel Duplicate Address Detection (DAD) state changes so assigned `/64` prefixes display instantly without manual pull-to-refresh.
- `App.kt` & Telemetry:
  - Completely excised Firebase Analytics, FirebaseCrashlytics, and Google Services plugins.
  - Release APKs auto-signed with debug keystore.
