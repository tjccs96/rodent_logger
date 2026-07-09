use csv::Writer;
use etherparse::PacketHeaders;
use pcap::Capture;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    let dir = std::path::Path::new(&home)
        .join("Documents")
        .join("rodent_logger")
        .join(subdir);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketFormat {
    pub opcode: u16,
    pub packet_len: usize,
    pub enemy_char_offset: usize,
    pub enemy_family_offset: usize,
    pub friendly_char_offset: usize,
    pub friendly_family_offset: usize,
    pub guild_marker_offset: usize,
    pub guild_flag_offset_from_marker: isize,
    pub guild_string_offset_from_marker: isize,
    #[serde(default)]
    pub guild_string_offset: usize,
}

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

pub fn find_all_bdo_strings(payload: &[u8]) -> Vec<(String, usize)> {
    let mut results: Vec<(String, usize)> = Vec::new();
    let mut i = 0;
    while i + 2 <= payload.len() {
        if payload[i] >= 0x20 && payload[i] <= 0x7E && payload[i + 1] == 0x00 {
            let s = read_bdo_string(payload, i);
            let len = s.len();
            if len >= 3
                && len <= 30
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation())
            {
                results.push((s, i));
                i += len * 2;
                continue;
            }
        }
        i += 1;
    }
    results
}

pub fn find_guild_marker(payload: &[u8]) -> Option<(usize, isize, isize)> {
    for i in 0..payload.len().saturating_sub(7) {
        if payload[i] == 0x06
            && payload[i + 1] == 0x00
            && payload[i + 2] == 0x00
            && payload[i + 3] == 0x00
        {
            // Scan forward from marker to find the next valid BDO string (guild name)
            let marker_end = i + 4;
            let search_end = (marker_end + 20).min(payload.len());
            for guild_off in marker_end..search_end {
                if payload[guild_off] >= 0x20
                    && payload[guild_off] <= 0x7E
                    && guild_off + 1 < payload.len()
                    && payload[guild_off + 1] == 0x00
                {
                    let guild = read_bdo_string(payload, guild_off);
                    if guild.len() >= 3
                        && guild
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation())
                    {
                        let (flag_rel, guild_rel) = if i % 2 == 1 {
                            (-1, guild_off as isize - i as isize)
                        } else {
                            if i >= 1 && payload[i - 1] <= 1 {
                                (-1, guild_off as isize - i as isize)
                            } else {
                                (4, guild_off as isize - i as isize)
                            }
                        };
                        return Some((i, flag_rel, guild_rel));
                    }
                }
            }
        }
    }
    None
}

fn build_streams_from_pcap<F>(input: &str, mut on_packet: F) -> Result<(), String>
where
    F: FnMut(bool, u16, usize, &[u8], &str),
{
    let mut cap =
        pcap::Capture::from_file(input).map_err(|e| format!("Failed to open pcap: {}", e))?;
    let mut streams: HashMap<(IpAddr, u16, IpAddr, u16), TcpState> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        let ts = format!(
            "{}.{:06}",
            packet.header.ts.tv_sec, packet.header.ts.tv_usec
        );

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
                                    let p_len =
                                        u16::from_le_bytes([state.buffer[i], state.buffer[i + 1]])
                                            as usize;
                                    if p_len >= 300 && p_len <= 400 && state.buffer[i + 2] == 0x00 {
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

                            on_packet(is_unencrypted, opcode, packet_len, bdo_packet, &ts);

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
    Ok(())
}

/// Attempting to auto detect the packet format in case PA shifts string order around/packet size or
/// where the byte for the kill  flag is
pub fn detect_format(input: &str, player_name: Option<&str>) -> Result<PacketFormat, String> {
    let target_bytes = player_name.map(|name| {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let mut bytes = Vec::with_capacity(utf16.len() * 2);
        for &c in &utf16 {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes
    });

    #[derive(Default)]
    struct Candidate {
        count: u32,
        representative: Option<Vec<u8>>,
    }

    let mut candidates: HashMap<(u16, usize), Candidate> = HashMap::new();

    build_streams_from_pcap(
        input,
        |is_unencrypted, opcode, packet_len, bdo_packet, _ts| {
            if !is_unencrypted || opcode == 0 || packet_len < 300 || packet_len > 500 {
                return;
            }

            if let Some(ref target) = target_bytes {
                if !bdo_packet.windows(target.len()).any(|w| w == target) {
                    return;
                }
            } else {
                let strings = find_all_bdo_strings(bdo_packet);
                if strings.len() < 4 {
                    return;
                }
            }

            let entry = candidates.entry((opcode, packet_len)).or_default();
            entry.count += 1;
            if entry.representative.is_none() {
                entry.representative = Some(bdo_packet.to_vec());
            }
        },
    )?;

    let best = candidates
        .into_iter()
        .max_by_key(|(_, c)| c.count)
        .ok_or_else(|| "No matchup event packets found in pcap".to_string())?;

    let (opcode, packet_len) = best.0;
    let packet = best
        .1
        .representative
        .ok_or_else(|| "No representative packet".to_string())?;

    let strings = find_all_bdo_strings(&packet);
    if strings.len() < 5 {
        return Err(format!(
            "Representative packet has fewer than 5 strings (found {})",
            strings.len()
        ));
    }

    let mut sorted = strings.clone();
    sorted.sort_by_key(|(_, off)| *off);

    let (marker_offset, mut flag_rel, guild_rel) = find_guild_marker(&packet).unwrap_or((0, 0, 0));

    // Override flag_rel: +4 is the standard position (right after 06 00 00 00).
    if marker_offset > 0 && marker_offset + 4 < packet.len() {
        flag_rel = 4;
    }

    let marker_target = if marker_offset > 0 {
        marker_offset + guild_rel as usize
    } else {
        0
    };

    // Detect format version by checking what the marker points to:
    // Format A (marker->sorted[2]): [enemy_char, friendly_char, guild, friendly_family, enemy_family]
    // Format B (marker->sorted[1]): [enemy_char, guild, friendly_char, friendly_family, enemy_family]
    // Format C (default):          [enemy_family, friendly_family, guild, friendly_char, enemy_char]
    let format = if marker_target > 0 && marker_target == sorted[2].1 {
        'A'
    } else if marker_target > 0 && marker_target == sorted[1].1 {
        'B'
    } else {
        'C'
    };

    let guild_offset = match format {
        'A' => sorted[2].1,
        'B' => sorted[1].1,
        _ => sorted[2].1,
    };

    let friendly_char_idx = match format {
        'A' => 1,
        'B' => 2,
        _ => 1,
    };

    let (
        mut friendly_char_offset,
        mut friendly_family_offset,
        mut enemy_char_offset,
        mut enemy_family_offset,
    ) = match format {
        'A' => {
            // Format A: s0=enemy_char, s1=friendly_char, s2=guild, s3=friendly_family, s4=enemy_family
            (sorted[1].1, sorted[3].1, sorted[0].1, sorted[4].1)
        }
        'B' => {
            // Format B: s0=enemy_char, s1=guild, s2=friendly_char, s3=friendly_family, s4=enemy_family
            (sorted[2].1, sorted[3].1, sorted[0].1, sorted[4].1)
        }
        _ => {
            // Format C: s0=enemy_char, s1=friendly_char, s2=guild, s3=friendly_family, s4=enemy_family
            (sorted[1].1, sorted[3].1, sorted[0].1, sorted[4].1)
        }
    };

    if format == 'C' && player_name.is_none() {
        let mut s0_overlap: u32 = 0;
        let mut s4_overlap: u32 = 0;
        let mut total: u32 = 0;

        let _ = build_streams_from_pcap(input, |is_unencrypted, op, pl, bdo_packet, _ts| {
            if !is_unencrypted || op != opcode || pl != packet_len {
                return;
            }
            let strs = find_all_bdo_strings(bdo_packet);
            if strs.len() < 5 {
                return;
            }
            let mut s = strs.clone();
            s.sort_by_key(|(_, off)| *off);

            let fc = &s[friendly_char_idx].0;
            if &s[0].0 == fc {
                s0_overlap += 1;
            }
            if &s[4].0 == fc {
                s4_overlap += 1;
            }
            total += 1;
        });

        if total > 5 && s4_overlap > s0_overlap && s4_overlap > total / 10 {
            enemy_char_offset = sorted[4].1;
            enemy_family_offset = sorted[0].1;
        }
    }

    // If --name given, match it against friendly_char or enemy_char
    if let Some(ref name) = player_name {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let mut name_bytes = Vec::with_capacity(utf16.len() * 2);
        for &c in &utf16 {
            name_bytes.extend_from_slice(&c.to_le_bytes());
        }
        let pos = packet
            .windows(name_bytes.len())
            .position(|w| w == name_bytes)
            .ok_or_else(|| format!("Player name '{}' not found in packet", name))?;

        if pos == friendly_char_offset {
            // Name matches friendly — keep default
        } else if pos == enemy_char_offset {
            // Name matches enemy — swap
            std::mem::swap(&mut friendly_char_offset, &mut enemy_char_offset);
            std::mem::swap(&mut friendly_family_offset, &mut enemy_family_offset);
        } else {
            let expected = match format {
                'A' => format!("{} or {}", sorted[0].1, sorted[1].1),
                'B' => format!("{} or {}", sorted[0].1, sorted[2].1),
                _ => format!("{} or {}", sorted[1].1, sorted[4].1),
            };
            return Err(format!(
                "Name '{}' not at a character offset (expected {})",
                name, expected
            ));
        }
    }

    Ok(PacketFormat {
        opcode,
        packet_len,
        enemy_char_offset,
        enemy_family_offset,
        friendly_char_offset,
        friendly_family_offset,
        guild_marker_offset: marker_offset,
        guild_flag_offset_from_marker: flag_rel,
        guild_string_offset_from_marker: guild_rel,
        guild_string_offset: guild_offset,
    })
}

pub fn packet_format_path() -> std::path::PathBuf {
    std::path::PathBuf::from("packet_format.json")
}

pub fn load_packet_formats() -> Vec<PacketFormat> {
    let path = packet_format_path();
    let json = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    if let Ok(formats) = serde_json::from_str::<Vec<PacketFormat>>(&json) {
        return formats;
    }
    if let Ok(fmt) = serde_json::from_str::<PacketFormat>(&json) {
        return vec![fmt];
    }
    Vec::new()
}

fn save_all_packet_formats(formats: &[PacketFormat]) -> Result<(), String> {
    let path = packet_format_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config dir: {}", e))?;
    }
    let json =
        serde_json::to_string_pretty(formats).map_err(|e| format!("Failed to serialize: {}", e))?;
    std::fs::write(&path, json).map_err(|e| format!("Failed to write config: {}", e))?;
    Ok(())
}

pub fn save_packet_format(fmt: &PacketFormat) -> Result<(), String> {
    let mut formats = load_packet_formats();
    if let Some(pos) = formats
        .iter()
        .position(|f| f.opcode == fmt.opcode && f.packet_len == fmt.packet_len)
    {
        formats[pos] = fmt.clone();
    } else {
        formats.push(fmt.clone());
    }
    save_all_packet_formats(&formats)
}

pub fn load_packet_format() -> Option<PacketFormat> {
    load_packet_formats().into_iter().last()
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
    let mut formats = load_packet_formats();
    if formats.is_empty() {
        if let Ok(fmt) = detect_format(input, None) {
            let _ = save_packet_format(&fmt);
            formats = vec![fmt];
        } else {
            return Err(
                "Could not detect packet format from pcap and no saved config found".to_string(),
            );
        }
    }

    let format_map: HashMap<(u16, usize), &PacketFormat> = formats
        .iter()
        .map(|f| ((f.opcode, f.packet_len), f))
        .collect();

    let mut cap =
        pcap::Capture::from_file(input).map_err(|e| format!("Failed to open pcap: {}", e))?;
    let mut wtr = Writer::from_path(output).map_err(|e| format!("Failed to create CSV: {}", e))?;

    wtr.write_record(&["Timestamp", "Event", "Guild", "Player 1", "Player 2"])
        .map_err(|e| format!("Failed to write CSV headers: {}", e))?;

    let mut count = 0;
    let mut streams: HashMap<(IpAddr, u16, IpAddr, u16), TcpState> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        let ts = format!(
            "{}.{:06}",
            packet.header.ts.tv_sec, packet.header.ts.tv_usec
        );

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
                                    let p_len =
                                        u16::from_le_bytes([state.buffer[i], state.buffer[i + 1]])
                                            as usize;
                                    if p_len >= 300 && p_len <= 400 && state.buffer[i + 2] == 0x00 {
                                        let cand_opcode = u16::from_le_bytes([
                                            state.buffer[i + 3],
                                            state.buffer[i + 4],
                                        ]);
                                        if format_map.contains_key(&(cand_opcode, p_len)) {
                                            offset = i;
                                            found_sync = true;
                                            break;
                                        }
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
                                if let Some(fmt) = format_map.get(&(opcode, packet_len)) {
                                    let enemy_char =
                                        read_bdo_string(bdo_packet, fmt.enemy_char_offset);
                                    let enemy_family =
                                        read_bdo_string(bdo_packet, fmt.enemy_family_offset);
                                    let friendly_char =
                                        read_bdo_string(bdo_packet, fmt.friendly_char_offset);
                                    let friendly_family =
                                        read_bdo_string(bdo_packet, fmt.friendly_family_offset);

                                    let mut enemy_guild = String::new();
                                    let mut is_death = false;

                                    // Use direct guild offset if available
                                    if fmt.guild_string_offset > 0
                                        && fmt.guild_string_offset < bdo_packet.len()
                                    {
                                        enemy_guild =
                                            read_bdo_string(bdo_packet, fmt.guild_string_offset);
                                    }

                                    // Find marker for kill/death flag
                                    for i in 0..bdo_packet.len().saturating_sub(7) {
                                        if bdo_packet[i] == 0x06
                                            && bdo_packet[i + 1] == 0x00
                                            && bdo_packet[i + 2] == 0x00
                                            && bdo_packet[i + 3] == 0x00
                                        {
                                            let flag_rel = fmt.guild_flag_offset_from_marker;
                                            let flag_idx = if flag_rel >= 0 {
                                                i + flag_rel as usize
                                            } else {
                                                i.saturating_sub((-flag_rel) as usize)
                                            };
                                            if flag_idx < bdo_packet.len() {
                                                is_death = bdo_packet[flag_idx] == 0x00;
                                            }

                                            // Fallback: if no direct guild offset, use marker-based guild
                                            if fmt.guild_string_offset == 0 {
                                                let guild_rel = fmt.guild_string_offset_from_marker;
                                                let guild_idx = if guild_rel >= 0 {
                                                    i + guild_rel as usize
                                                } else {
                                                    i.saturating_sub((-guild_rel) as usize)
                                                };
                                                if guild_idx < bdo_packet.len() {
                                                    enemy_guild =
                                                        read_bdo_string(bdo_packet, guild_idx);
                                                }
                                            }
                                            break;
                                        }
                                    }

                                    let event_str = if is_death { "Death" } else { "Kill" };
                                    let friendly_name =
                                        format!("{} ({})", friendly_family, friendly_char);
                                    let enemy_name = format!("{} ({})", enemy_family, enemy_char);

                                    wtr.write_record(&[
                                        &ts,
                                        event_str,
                                        &enemy_guild,
                                        &friendly_name,
                                        &enemy_name,
                                    ])
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

    wtr.flush()
        .map_err(|e| format!("Failed to flush CSV writer: {}", e))?;

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

    let total_allied_players = stats_map.len();
    out.push_str(&format!(
        "\n================ Allied K/D Summary (Players: {}) ================\n",
        total_allied_players
    ));
    out.push_str(&format!(
        "{:<35} | {:<6} | {:<6} | {:<5}\n",
        "Family (Character)", "Kills", "Deaths", "K/D"
    ));
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
            "--- {} (Players: {}, K: {} D: {} K/D: {:.2}) ---\n",
            guild_name,
            players.len(),
            g_stats.kills,
            g_stats.deaths,
            g_kd
        ));
        out.push_str(&format!(
            "  {:<35} | {:<6} | {:<6} | {:<5}\n",
            "Family (Character)", "Kills", "Deaths", "K/D"
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
    out.push_str(&format!(
        "{:<35} | {:<7} | {:<6} | {:<6} | {:<5}\n",
        "Guild Name", "Players", "Kills", "Deaths", "K/D"
    ));
    out.push_str("-----------------------------------------------------------------\n");

    let mut guild_stats_vec: Vec<(&String, &GuildStats)> = enemy_guild_stats.iter().collect();
    guild_stats_vec.sort_by(|a, b| b.1.kills.cmp(&a.1.kills));

    for (guild, stats) in &guild_stats_vec {
        let kd = if stats.deaths == 0 {
            stats.kills as f32
        } else {
            stats.kills as f32 / stats.deaths as f32
        };
        let player_count = enemy_per_guild.get(*guild).map_or(0, |p| p.len());
        out.push_str(&format!(
            "{:<35} | {:<7} | {:<6} | {:<6} | {:<5.2}\n",
            guild, player_count, stats.kills, stats.deaths, kd
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
    out.push_str(&format!(
        "{:<19} | {:<6} | {:<6} | {:<5}\n",
        "Team", "Kills", "Deaths", "K/D"
    ));
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
