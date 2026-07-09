use csv::Writer;
use etherparse::PacketHeaders;
use pcap::Capture;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn home_for_user(username: &str) -> Option<String> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() > 5 && parts[0] == username {
            return Some(parts[5].to_string());
        }
    }
    None
}

pub fn rodent_logger_dir(subdir: &str) -> std::path::PathBuf {
    let home = if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        home_for_user(&sudo_user)
            .or_else(|| std::env::var("HOME").ok())
            .unwrap_or_else(|| format!("/home/{}", sudo_user))
    } else {
        std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
    };
    let dir = std::path::Path::new(&home).join("Documents").join("rodent_logger").join(subdir);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub const NW_OPCODE: u16 = 0x0DA4;
pub const NW_NEW_OPCODE: u16 = 0x1CD6;

pub struct TcpState {
    pub buffer: Vec<u8>,
    pub next_seq: u32,
}

#[derive(Default)]
pub struct PlayerStats {
    pub kills: u32,
    pub deaths: u32,
}

#[derive(Default)]
pub struct GuildStats {
    pub kills: u32,
    pub deaths: u32,
}

pub fn read_bdo_string(payload: &[u8], start: usize) -> String {
    let max_len = 62;
    if start + 2 > payload.len() {
        return String::new();
    }
    let end_limit = (start + max_len).min(payload.len());
    let buf = &payload[start..end_limit];
    let mut u16_chars = Vec::new();

    for chunk in buf.chunks_exact(2) {
        let val = u16::from_le_bytes([chunk[0], chunk[1]]);
        if val == 0 {
            break;
        }
        u16_chars.push(val);
    }

    String::from_utf16_lossy(&u16_chars)
}

pub fn capture(
    interface: &str,
    output: &str,
    filter: Option<&str>,
    running: Arc<AtomicBool>,
    progress: &AtomicU64,
) -> Result<u64, String> {
    let mut cap = Capture::from_device(interface)
        .map_err(|e| format!("Failed to open device: {}", e))?
        .promisc(true)
        .snaplen(65535)
        .timeout(100)
        .open()
        .map_err(|e| format!("Failed to open capture: {}", e))?;

    if let Some(f) = filter {
        if !f.is_empty() {
            cap.filter(f, true)
                .map_err(|e| format!("Failed to set filter: {}", e))?;
        }
    }

    let break_handle = cap.breakloop_handle();
    let running_watcher = running.clone();
    thread::spawn(move || {
        while running_watcher.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(50));
        }
        break_handle.breakloop();
    });

    let mut savefile = cap
        .savefile(output)
        .map_err(|e| format!("Failed to create savefile: {}", e))?;

    let mut packet_count = 0;

    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                savefile.write(&packet);
                packet_count += 1;
                progress.store(packet_count, Ordering::SeqCst);

                if let Ok((eth, rest)) = etherparse::Ethernet2Header::from_slice(packet.data) {
                    if eth.ether_type == etherparse::EtherType::IPV4 {
                        if let Ok((ipv4, _)) = etherparse::Ipv4Header::from_slice(rest) {
                            let src = Ipv4Addr::from(ipv4.source);
                            let dst = Ipv4Addr::from(ipv4.destination);
                            print!("\r[{}] {} -> {}  ", packet_count, src, dst);
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(format!("Capture error: {}", e)),
        }
    }

    drop(savefile);
    Ok(packet_count)
}

pub fn export_csv(input: &str, output: &str) -> Result<u64, String> {
    let mut cap = pcap::Capture::from_file(input).map_err(|e| format!("Failed to open pcap: {}", e))?;
    let mut wtr = Writer::from_path(output).map_err(|e| format!("Failed to create CSV: {}", e))?;

    wtr.write_record(&["Timestamp", "Event", "Guild", "Player 1", "Player 2"])
        .map_err(|e| format!("Failed to write CSV headers: {}", e))?;

    let mut count = 0;
    let mut streams: HashMap<(IpAddr, u16, IpAddr, u16), TcpState> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        let ts = format!("{}.{:06}", packet.header.ts.tv_sec, packet.header.ts.tv_usec);

        if let Ok(headers) = PacketHeaders::from_ethernet_slice(packet.data) {
            if let Some(ip_header) = headers.net {
                let (src_ip, dst_ip) = match ip_header {
                    etherparse::NetHeaders::Ipv4(ipv4, _) => (
                        IpAddr::V4(std::net::Ipv4Addr::from(ipv4.source)),
                        IpAddr::V4(std::net::Ipv4Addr::from(ipv4.destination)),
                    ),
                    etherparse::NetHeaders::Ipv6(ipv6, _) => (
                        IpAddr::V6(std::net::Ipv6Addr::from(ipv6.source)),
                        IpAddr::V6(std::net::Ipv6Addr::from(ipv6.destination)),
                    ),
                    _ => continue,
                };

                if let Some(transport) = headers.transport {
                    if let etherparse::TransportHeader::Tcp(tcp) = transport {
                        let payload = headers.payload.slice();
                        if payload.is_empty() {
                            continue;
                        }

                        let key = (src_ip, tcp.source_port, dst_ip, tcp.destination_port);
                        let state = streams.entry(key).or_insert_with(|| TcpState {
                            buffer: Vec::new(),
                            next_seq: tcp.sequence_number,
                        });

                        let seq = tcp.sequence_number;
                        let payload_len = payload.len() as u32;

                        if seq == state.next_seq {
                            state.buffer.extend_from_slice(payload);
                            state.next_seq = seq.wrapping_add(payload_len);
                        } else if (seq.wrapping_sub(state.next_seq) as i32) < 0 {
                            let diff = state.next_seq.wrapping_sub(seq) as usize;
                            if payload.len() > diff {
                                state.buffer.extend_from_slice(&payload[diff..]);
                                state.next_seq =
                                    state.next_seq.wrapping_add((payload.len() - diff) as u32);
                            }
                        } else {
                            state.buffer.clear();
                            state.buffer.extend_from_slice(payload);
                            state.next_seq = seq.wrapping_add(payload_len);
                        }

                        let mut offset = 0;

                        while offset + 5 <= state.buffer.len() {
                            let packet_len = u16::from_le_bytes([
                                state.buffer[offset],
                                state.buffer[offset + 1],
                            ]) as usize;

                            if packet_len < 5 || packet_len > 1000 {
                                let mut found_sync = false;
                                for i in (offset + 1)..state.buffer.len().saturating_sub(5) {
                                    if state.buffer[i] == 0x68
                                        && state.buffer[i + 1] == 0x01
                                        && state.buffer[i + 2] == 0x00
                                        && state.buffer[i + 3] == 0xA4
                                        && state.buffer[i + 4] == 0x0D
                                    {
                                        offset = i;
                                        found_sync = true;
                                        break;
                                    }
                                    if state.buffer[i] == 0x64
                                        && state.buffer[i + 1] == 0x01
                                        && state.buffer[i + 2] == 0x00
                                        && state.buffer[i + 3] == 0xD6
                                        && state.buffer[i + 4] == 0x1C
                                    {
                                        offset = i;
                                        found_sync = true;
                                        break;
                                    }
                                }
                                if !found_sync {
                                    state.buffer.clear();
                                    offset = 0;
                                    break;
                                }
                                continue;
                            }

                            if offset + packet_len > state.buffer.len() {
                                break;
                            }

                            let bdo_packet = &state.buffer[offset..offset + packet_len];
                            let is_unencrypted = bdo_packet[2] == 0x00;
                            let opcode = u16::from_le_bytes([bdo_packet[3], bdo_packet[4]]);

                            if is_unencrypted {
                                let is_matchup = (opcode == NW_OPCODE && packet_len == 360)
                                    || (opcode == NW_NEW_OPCODE && packet_len == 356);

                                if is_matchup {
                                    let (enemy_char, enemy_family, friendly_char, friendly_family, _guild_scan_start, _guild_scan_end) =
                                        if packet_len == 356 {
                                            (
                                                read_bdo_string(bdo_packet, 5),
                                                read_bdo_string(bdo_packet, 260),
                                                read_bdo_string(bdo_packet, 136),
                                                read_bdo_string(bdo_packet, 198),
                                                50,
                                                150,
                                            )
                                        } else {
                                            (
                                                read_bdo_string(bdo_packet, 5),
                                                read_bdo_string(bdo_packet, 202),
                                                read_bdo_string(bdo_packet, 67),
                                                read_bdo_string(bdo_packet, 264),
                                                120,
                                                150,
                                            )
                                        };

                                    let mut enemy_guild = String::new();
                                    let mut is_death = false;

                                    for i in 50..=180 {
                                        if i + 7 < bdo_packet.len()
                                            && bdo_packet[i] == 0x06
                                            && bdo_packet[i + 1] == 0x00
                                            && bdo_packet[i + 2] == 0x00
                                            && bdo_packet[i + 3] == 0x00
                                        {
                                            if packet_len == 356 {
                                                let flag = bdo_packet[i + 4];
                                                is_death = flag == 0x00;
                                                enemy_guild = read_bdo_string(bdo_packet, i + 7);
                                            } else {
                                                let flag = bdo_packet[i - 1];
                                                is_death = flag == 0x00;
                                                enemy_guild = read_bdo_string(bdo_packet, i + 4);
                                            }
                                            break;
                                        }
                                    }

                                    let event_str = if is_death { "Death" } else { "Kill" };
                                    let friendly_name = format!("{} ({})", friendly_char, friendly_family);
                                    let enemy_name = format!("{} ({})", enemy_char, enemy_family);

                                    wtr.write_record(&[&ts, event_str, &enemy_guild, &friendly_name, &enemy_name])
                                        .map_err(|e| format!("Failed to write CSV record: {}", e))?;

                                    count += 1;
                                }
                            }

                            offset += packet_len;
                        }

                        if offset > 0 {
                            state.buffer.drain(0..offset);
                        }
                    }
                }
            }
        }
    }

    wtr.flush().map_err(|e| format!("Failed to flush CSV writer: {}", e))?;

    Ok(count)
}

pub fn generate_stats(input: &str) -> String {
    let mut rdr = match csv::Reader::from_path(input) {
        Ok(r) => r,
        Err(e) => return format!("Failed to open CSV file '{}': {}", input, e),
    };

    let mut stats_map: HashMap<String, PlayerStats> = HashMap::new();
    let mut enemy_per_guild: HashMap<String, HashMap<String, PlayerStats>> = HashMap::new();
    let mut enemy_guild_stats: HashMap<String, GuildStats> = HashMap::new();

    for result in rdr.records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };

        if record.len() < 5 {
            continue;
        }

        let event = &record[1];
        let guild = &record[2];
        let player_1 = &record[3];
        let player_2 = &record[4];
        let is_death = event.to_lowercase() == "death";

        let p_stats = stats_map.entry(player_1.to_string()).or_default();
        if is_death {
            p_stats.deaths += 1;
        } else {
            p_stats.kills += 1;
        }

        let guild_key = if guild.trim().is_empty() {
            "No Guild".to_string()
        } else {
            guild.to_string()
        };

        let guild_players = enemy_per_guild.entry(guild_key.clone()).or_default();
        let e_stats = guild_players.entry(player_2.to_string()).or_default();
        if is_death {
            e_stats.kills += 1;
        } else {
            e_stats.deaths += 1;
        }

        let g_stats = enemy_guild_stats.entry(guild_key).or_default();
        if is_death {
            g_stats.kills += 1;
        } else {
            g_stats.deaths += 1;
        }
    }

    let mut out = String::new();

    out.push_str("\n================ Allied K/D Summary ================\n");
    out.push_str(&format!("{:<35} | {:<6} | {:<6} | {:<5}\n", "Player (Family)", "Kills", "Deaths", "K/D"));
    out.push_str("----------------------------------------------------\n");

    let mut allied_stats_vec: Vec<(&String, &PlayerStats)> = stats_map.iter().collect();
    allied_stats_vec.sort_by(|a, b| b.1.kills.cmp(&a.1.kills));

    for (player, stats) in &allied_stats_vec {
        let kd = if stats.deaths == 0 {
            stats.kills as f32
        } else {
            stats.kills as f32 / stats.deaths as f32
        };
        out.push_str(&format!(
            "{:<35} | {:<6} | {:<6} | {:<5.2}\n",
            player, stats.kills, stats.deaths, kd
        ));
    }
    out.push_str("====================================================\n\n");

    out.push_str("================ Enemy Player K/D Per Guild ================\n");

    let mut guild_names: Vec<&String> = enemy_per_guild.keys().collect();
    guild_names.sort();

    for guild_name in &guild_names {
        let players = &enemy_per_guild[*guild_name];
        let mut player_vec: Vec<(&String, &PlayerStats)> = players.iter().collect();
        player_vec.sort_by(|a, b| b.1.kills.cmp(&a.1.kills));

        let g_stats = enemy_guild_stats.get(*guild_name).unwrap();
        let g_kd = if g_stats.deaths == 0 {
            g_stats.kills as f32
        } else {
            g_stats.kills as f32 / g_stats.deaths as f32
        };

        out.push_str(&format!(
            "--- {} (K: {} D: {} K/D: {:.2}) ---\n",
            guild_name, g_stats.kills, g_stats.deaths, g_kd
        ));
        out.push_str(&format!(
            "  {:<35} | {:<6} | {:<6} | {:<5}\n",
            "Player (Family)", "Kills", "Deaths", "K/D"
        ));

        for (player, stats) in &player_vec {
            let kd = if stats.deaths == 0 {
                stats.kills as f32
            } else {
                stats.kills as f32 / stats.deaths as f32
            };
            out.push_str(&format!(
                "  {:<35} | {:<6} | {:<6} | {:<5.2}\n",
                player, stats.kills, stats.deaths, kd
            ));
        }
        out.push('\n');
    }
    out.push_str("==========================================================\n\n");

    out.push_str("================ Enemy Guild K/D Summary ================\n");
    out.push_str(&format!("{:<35} | {:<6} | {:<6} | {:<5}\n", "Guild Name", "Kills", "Deaths", "K/D"));
    out.push_str("---------------------------------------------------------\n");

    let mut guild_stats_vec: Vec<(&String, &GuildStats)> = enemy_guild_stats.iter().collect();
    guild_stats_vec.sort_by(|a, b| b.1.kills.cmp(&a.1.kills));

    for (guild, stats) in &guild_stats_vec {
        let kd = if stats.deaths == 0 {
            stats.kills as f32
        } else {
            stats.kills as f32 / stats.deaths as f32
        };
        out.push_str(&format!(
            "{:<35} | {:<6} | {:<6} | {:<5.2}\n",
            guild, stats.kills, stats.deaths, kd
        ));
    }
    out.push_str("=========================================================\n\n");

    let total_allied_kills: u32 = stats_map.values().map(|s| s.kills).sum();
    let total_allied_deaths: u32 = stats_map.values().map(|s| s.deaths).sum();

    let allied_kd = if total_allied_deaths == 0 {
        total_allied_kills as f32
    } else {
        total_allied_kills as f32 / total_allied_deaths as f32
    };

    let total_enemy_kills = total_allied_deaths;
    let total_enemy_deaths = total_allied_kills;

    let enemy_kd = if total_enemy_deaths == 0 {
        total_enemy_kills as f32
    } else {
        total_enemy_kills as f32 / total_enemy_deaths as f32
    };

    out.push_str("================ Overall Team Stats ================\n");
    out.push_str(&format!("{:<19} | {:<6} | {:<6} | {:<5}\n", "Team", "Kills", "Deaths", "K/D"));
    out.push_str("----------------------------------------------------\n");
    out.push_str(&format!(
        "{:<19} | {:<6} | {:<6} | {:<5.2}\n",
        "Allies (Alliance)", total_allied_kills, total_allied_deaths, allied_kd
    ));
    out.push_str(&format!(
        "{:<19} | {:<6} | {:<6} | {:<5.2}\n",
        "Enemies", total_enemy_kills, total_enemy_deaths, enemy_kd
    ));
    out.push_str("====================================================\n");

    out
}
