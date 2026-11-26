use std::collections::HashMap;
use std::io;
use std::net::Ipv6Addr;

use crate::firewall::{self, IptablesTarget};
use crate::report;
use vpnhotspotd::shared::ipv4_forward_counter::{
    parse_ipv4_forward_counter_line, Ipv4ForwardCounter, Ipv4ForwardKey,
};
use vpnhotspotd::shared::model::SessionConfig;
use vpnhotspotd::shared::proto::daemon;

pub(crate) async fn read_counters(
    configs: &[SessionConfig],
) -> io::Result<Vec<daemon::TrafficCounter>> {
    let has_ipv4 = !configs.iter().all(|config| config.disable_ipv4);
    let has_ipv6 = configs.iter().any(|config| config.routed_ipv6_prefix.is_some());
    if !has_ipv4 && !has_ipv6 {
        return Ok(Vec::new());
    }

    let mut result = Vec::new();

    // 1. IPv4 Counters
    if has_ipv4 {
        let client_macs_v4 = client_macs(configs);
        if !client_macs_v4.is_empty() {
            let mut counters = HashMap::new();
            let _ = firewall::restore_stdout_lines(
                IptablesTarget::Ipv4,
                "*filter\n-nvx -L vpnhotspot_stats\nCOMMIT\n",
                |line| {
                    if !is_counter_line(line) {
                        return;
                    }
                    let Some(line) = (match parse_ipv4_forward_counter_line(line) {
                        Ok(line) => line,
                        Err(e) => {
                            report::stdout!("{e}");
                            None
                        }
                    }) else {
                        return;
                    };
                    let Some(mac) = client_macs_v4.get(&line.key) else {
                        return;
                    };
                    let counter = counters
                        .entry(line.key)
                        .or_insert_with(|| Ipv4ForwardCounter::new(*mac));
                    counter.update_if_missing(line.direction, line.packets, line.bytes);
                },
            )
            .await;
            result.extend(
                counters
                    .into_iter()
                    .filter_map(|(key, counter)| counter.into_proto(key)),
            );
        }
    }

    // 2. IPv6 Counters
    if has_ipv6 {
        let mut client_macs_v6: HashMap<(String, Ipv6Addr), [u8; 6]> = HashMap::new();
        for config in configs {
            if config.routed_ipv6_prefix.is_none() {
                continue;
            }
            for client in &config.clients {
                for address in &client.ipv6 {
                    client_macs_v6.insert((config.downstream.clone(), *address), client.mac);
                }
            }
        }
        if !client_macs_v6.is_empty() {
            struct V6Counter {
                mac: [u8; 6],
                sent_packets: u64,
                sent_bytes: u64,
                received_packets: u64,
                received_bytes: u64,
            }
            let mut counters: HashMap<(String, Ipv6Addr), V6Counter> = HashMap::new();
            let _ = firewall::restore_stdout_lines(
                IptablesTarget::Ipv6,
                "*filter\n-nvx -L vpnhotspot_stats\nCOMMIT\n",
                |line| {
                    if !is_counter_line(line) {
                        return;
                    }
                    let mut cols = line.split_whitespace();
                    let (Some(pkts_s), Some(bytes_s), Some(target)) =
                        (cols.next(), cols.next(), cols.next())
                    else {
                        return;
                    };
                    if target != "ACCEPT" {
                        return;
                    }
                    let (Some(_), Some(_), Some(input), Some(output), Some(source), Some(dest)) =
                        (cols.next(), cols.next(), cols.next(), cols.next(), cols.next(), cols.next())
                    else {
                        return;
                    };
                    let Ok(packets) = pkts_s.parse::<u64>() else { return; };
                    let Ok(bytes) = bytes_s.parse::<u64>() else { return; };

                    let is_received = source == "::/0" || source == "anywhere";
                    let is_sent = dest == "::/0" || dest == "anywhere";
                    if is_received == is_sent {
                        return;
                    }

                    let addr_str = if is_received { dest } else { source };
                    let Ok(addr) = addr_str.parse::<Ipv6Addr>() else { return; };
                    let downstream = (if is_received { output } else { input }).to_string();

                    let key = (downstream, addr);
                    let Some(mac) = client_macs_v6.get(&key) else { return; };
                    let counter = counters.entry(key).or_insert_with(|| V6Counter {
                        mac: *mac,
                        sent_packets: 0,
                        sent_bytes: 0,
                        received_packets: 0,
                        received_bytes: 0,
                    });
                    if is_sent {
                        if counter.sent_packets == 0 {
                            counter.sent_packets = packets;
                            counter.sent_bytes = bytes;
                        }
                    } else {
                        if counter.received_packets == 0 {
                            counter.received_packets = packets;
                            counter.received_bytes = bytes;
                        }
                    }
                },
            )
            .await;

            for ((downstream, addr), c) in counters {
                result.push(daemon::TrafficCounter {
                    mac: c.mac.to_vec(),
                    downstream,
                    source: Some(daemon::TrafficCounterSource {
                        source: Some(daemon::traffic_counter_source::Source::Ipv6ForwardAddress(
                            addr.octets().to_vec(),
                        )),
                    }),
                    sent_packets: c.sent_packets,
                    sent_bytes: c.sent_bytes,
                    received_packets: c.received_packets,
                    received_bytes: c.received_bytes,
                });
            }
        }
    }

    Ok(result)
}

fn is_counter_line(line: &str) -> bool {
    let mut columns = line.split_whitespace();
    columns
        .next()
        .is_some_and(|value| value.parse::<u64>().is_ok())
        && columns
            .next()
            .is_some_and(|value| value.parse::<u64>().is_ok())
}

fn client_macs(configs: &[SessionConfig]) -> HashMap<Ipv4ForwardKey, [u8; 6]> {
    let mut result = HashMap::new();
    for config in configs {
        for client in &config.clients {
            for address in &client.ipv4 {
                result.insert(
                    Ipv4ForwardKey {
                        downstream: config.downstream.clone(),
                        address: *address,
                    },
                    client.mac,
                );
            }
        }
    }
    result
}
