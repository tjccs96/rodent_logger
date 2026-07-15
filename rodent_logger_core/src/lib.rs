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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub is_death_value: u8,
    #[serde(default)]
    pub old_format: bool,
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
        let end_limit = (i + 62).min(payload.len());
        let has_terminator = payload[i..end_limit]
            .chunks_exact(2)
            .any(|pair| pair == [0x00, 0x00]);
        if payload[i] >= 0x20 && payload[i] <= 0x7E && payload[i + 1] == 0x00 && has_terminator {
            let s = read_bdo_string(payload, i);
            let len = s.encode_utf16().count();
            if len >= 3 && len <= 30 && s.chars().all(|c| !c.is_control() && c != '\u{fffd}') {
                results.push((s, i));
                i += len * 2;
                continue;
            }
        }
        i += 1;
    }
    results
}

fn uppercase_ratio(s: &str) -> f32 {
    let letters: Vec<char> = s.chars().filter(|c| c.is_alphabetic()).collect();
    if letters.is_empty() {
        return 0.0;
    }
    let uppercase = letters.iter().filter(|c| c.is_uppercase()).count();
    uppercase as f32 / letters.len() as f32
}

pub fn find_guild_marker(
    payload: &[u8],
    strings: &[(String, usize)],
    opcode: u16,
    packet_len: usize,
    known_formats: &[PacketFormat],
) -> Option<(usize, isize, usize)> {
    for i in 0..payload.len().saturating_sub(7) {
        if payload[i] == 0x06
            && payload[i + 1] == 0x00
            && payload[i + 2] == 0x00
            && payload[i + 3] == 0x00
        {
            let before = strings.iter().rev().find(|(_, off)| *off < i);
            let after = strings.iter().find(|(_, off)| *off > i);

            let known = known_formats
                .iter()
                .find(|f| f.opcode == opcode && f.packet_len == packet_len);

            let guild_off = if let Some(k) = known {
                if k.guild_string_offset_from_marker < 0 {
                    before
                        .map(|(_, off)| *off)
                        .or_else(|| after.map(|(_, off)| *off))?
                } else {
                    after
                        .map(|(_, off)| *off)
                        .or_else(|| before.map(|(_, off)| *off))?
                }
            } else {
                match (before, after) {
                    (Some((b, b_off)), Some((a, a_off))) => {
                        let b_ratio = uppercase_ratio(b);
                        let a_ratio = uppercase_ratio(a);
                        if b_ratio > a_ratio {
                            *b_off
                        } else if a_ratio > b_ratio {
                            *a_off
                        } else {
                            if i - b_off <= a_off - i {
                                *b_off
                            } else {
                                *a_off
                            }
                        }
                    }
                    (Some((_, b_off)), None) => *b_off,
                    (None, Some((_, a_off))) => *a_off,
                    (None, None) => continue,
                }
            };

            // The kill/death flag is a single byte with value 0x00 or 0x01.
            // In older packets it sits right after the marker (+4); in newer
            // packets it sits five bytes after the marker (+5).
            let flag_rel = if let Some(k) = known {
                k.guild_flag_offset_from_marker
            } else {
                let after4 = payload.get(i + 4).copied().unwrap_or(0xFF);
                let after5 = payload.get(i + 5).copied().unwrap_or(0xFF);
                if after4 <= 1 {
                    4
                } else if after5 <= 1 {
                    5
                } else {
                    -1
                }
            };
            return Some((i, flag_rel, guild_off));
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

/// Convert a Rust string to UTF-16LE bytes including the null terminator.
fn utf16le_bytes_with_null(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(utf16.len() * 2 + 2);
    for &c in &utf16 {
        bytes.extend_from_slice(&c.to_le_bytes());
    }
    bytes.extend_from_slice(&[0x00, 0x00]);
    bytes
}

/// Find the most common event packet in a pcap and return all readable BDO
/// strings with their byte offsets. This is used by the interactive calibrate
/// mode so the user can pick which string is the friendly char, family, etc.
pub fn find_calibration_candidates(
    input: &str,
) -> Result<(u16, usize, String, Vec<(String, usize)>), String> {
    #[derive(Default)]
    struct Candidate {
        count: u32,
        representative: Option<(Vec<u8>, String)>,
    }

    let mut candidates: HashMap<(u16, usize), Candidate> = HashMap::new();

    build_streams_from_pcap(
        input,
        |is_unencrypted, opcode, packet_len, bdo_packet, ts| {
            if !is_unencrypted || opcode == 0 || packet_len < 300 || packet_len > 500 {
                return;
            }
            let strings = find_all_bdo_strings(bdo_packet);
            if strings.len() < 5 {
                return;
            }

            let entry = candidates.entry((opcode, packet_len)).or_default();
            entry.count += 1;
            if entry.representative.is_none() {
                entry.representative = Some((bdo_packet.to_vec(), ts.to_string()));
            }
        },
    )?;

    let best = candidates
        .into_iter()
        .max_by_key(|(_, c)| c.count)
        .ok_or_else(|| "No event packets found in pcap".to_string())?;

    let (opcode, packet_len) = best.0;
    let (packet, ts) = best
        .1
        .representative
        .ok_or_else(|| "No representative packet".to_string())?;

    let mut strings = find_all_bdo_strings(&packet);
    strings.sort_by_key(|(_, off)| *off);

    Ok((opcode, packet_len, ts, strings))
}

/// Calibrate a new packet format from a pcap containing a known event.
///
/// The user provides the friendly/enemy character/family names that
/// appear in a single packet, plus whether that packet represents a kill or
/// death. The function locates the packet, derives all string offsets, finds
/// the guild marker, determines the kill/death flag, and returns a
/// `PacketFormat` ready to be saved to `known_formats.json`.
///
/// Note: this requires all five strings to be present in the packet.
pub fn calibrate_format(
    input: &str,
    friendly_char: &str,
    friendly_family: &str,
    enemy_char: &str,
    enemy_family: &str,
    enemy_guild: &str,
    event: &str,
) -> Result<PacketFormat, String> {
    let event_lower = event.to_lowercase();
    if event_lower != "kill" && event_lower != "death" {
        return Err("event must be 'kill' or 'death'".to_string());
    }

    let friendly_char_bytes = utf16le_bytes_with_null(friendly_char);
    let friendly_family_bytes = utf16le_bytes_with_null(friendly_family);
    let enemy_char_bytes = utf16le_bytes_with_null(enemy_char);
    let enemy_family_bytes = utf16le_bytes_with_null(enemy_family);
    let enemy_guild_bytes = utf16le_bytes_with_null(enemy_guild);

    let mut found_packet: Option<(u16, usize, Vec<u8>)> = None;

    build_streams_from_pcap(
        input,
        |is_unencrypted, opcode, packet_len, bdo_packet, _ts| {
            if found_packet.is_some()
                || !is_unencrypted
                || opcode == 0
                || packet_len < 300
                || packet_len > 500
            {
                return;
            }

            let has_all = bdo_packet
                .windows(friendly_char_bytes.len())
                .any(|w| w == friendly_char_bytes)
                && bdo_packet
                    .windows(friendly_family_bytes.len())
                    .any(|w| w == friendly_family_bytes)
                && bdo_packet
                    .windows(enemy_char_bytes.len())
                    .any(|w| w == enemy_char_bytes)
                && bdo_packet
                    .windows(enemy_family_bytes.len())
                    .any(|w| w == enemy_family_bytes)
                && bdo_packet
                    .windows(enemy_guild_bytes.len())
                    .any(|w| w == enemy_guild_bytes);

            if has_all {
                found_packet = Some((opcode, packet_len, bdo_packet.to_vec()));
            }
        },
    )?;

    let (opcode, packet_len, packet) = found_packet
        .ok_or_else(|| "No packet containing all provided names was found".to_string())?;

    fn find_offset(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    let friendly_char_offset = find_offset(&packet, &friendly_char_bytes)
        .ok_or_else(|| format!("friendly char '{}' not found in packet", friendly_char))?;
    let friendly_family_offset = find_offset(&packet, &friendly_family_bytes)
        .ok_or_else(|| format!("friendly family '{}' not found in packet", friendly_family))?;
    let enemy_char_offset = find_offset(&packet, &enemy_char_bytes)
        .ok_or_else(|| format!("enemy char '{}' not found in packet", enemy_char))?;
    let enemy_family_offset = find_offset(&packet, &enemy_family_bytes)
        .ok_or_else(|| format!("enemy family '{}' not found in packet", enemy_family))?;
    let enemy_guild_offset = find_offset(&packet, &enemy_guild_bytes)
        .ok_or_else(|| format!("enemy guild '{}' not found in packet", enemy_guild))?;

    // Find the guild marker.
    let mut marker_offset = 0;
    let mut flag_rel: isize = -1;
    for i in 0..packet.len().saturating_sub(7) {
        if packet[i] == 0x06
            && packet[i + 1] == 0x00
            && packet[i + 2] == 0x00
            && packet[i + 3] == 0x00
        {
            marker_offset = i;
            // Prefer +5 (newer format), fall back to +4 (older format).
            if packet.get(i + 5).copied().unwrap_or(0xFF) <= 1 {
                flag_rel = 5;
            } else if packet.get(i + 4).copied().unwrap_or(0xFF) <= 1 {
                flag_rel = 4;
            }
            break;
        }
    }

    if marker_offset == 0 {
        return Err("Guild marker (0x06 00 00 00) not found in packet".to_string());
    }
    if flag_rel < 0 {
        return Err("Could not determine kill/death flag offset from marker".to_string());
    }

    let flag_value = packet[marker_offset + flag_rel as usize];
    let is_death_value = if event_lower == "death" {
        flag_value
    } else {
        1 - flag_value
    };

    Ok(PacketFormat {
        opcode,
        packet_len,
        enemy_char_offset,
        enemy_family_offset,
        friendly_char_offset,
        friendly_family_offset,
        guild_marker_offset: marker_offset,
        guild_flag_offset_from_marker: flag_rel,
        guild_string_offset_from_marker: enemy_guild_offset as isize - marker_offset as isize,
        guild_string_offset: enemy_guild_offset,
        is_death_value,
        old_format: false,
    })
}

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
    let known_formats = load_known_formats();
    // Packets containing the player name, keyed by (opcode, packet_len), so
    // orientation uses the same format as the detected one.
    let mut name_representatives: HashMap<(u16, usize), Vec<u8>> = HashMap::new();

    build_streams_from_pcap(
        input,
        |is_unencrypted, opcode, packet_len, bdo_packet, _ts| {
            if !is_unencrypted || opcode == 0 || packet_len < 300 || packet_len > 500 {
                return;
            }

            let strings = find_all_bdo_strings(bdo_packet);
            if strings.len() < 4 {
                return;
            }

            if !find_guild_marker(bdo_packet, &strings, opcode, packet_len, &known_formats)
                .is_some_and(|(_, flag_rel, _)| flag_rel >= 0)
            {
                return;
            }

            let entry = candidates.entry((opcode, packet_len)).or_default();
            entry.count += 1;
            if entry.representative.is_none() {
                entry.representative = Some(bdo_packet.to_vec());
            }

            if let Some(ref target) = target_bytes {
                if !name_representatives.contains_key(&(opcode, packet_len))
                    && bdo_packet.windows(target.len()).any(|w| w == target)
                {
                    name_representatives.insert((opcode, packet_len), bdo_packet.to_vec());
                }
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

    // For orientation, use a packet of the same (opcode, packet_len) that
    // actually contains the player name.
    let orient_packet = if player_name.is_some() {
        name_representatives
            .get(&(opcode, packet_len))
            .ok_or_else(|| "Player name not found in any event packet".to_string())?
    } else {
        &packet
    };

    let mut strings = find_all_bdo_strings(&packet);
    strings.sort_by_key(|(_, off)| *off);

    // Find the guild marker and the guild string it points to.
    let (marker_offset, flag_rel, guild_string_offset) =
        find_guild_marker(&packet, &strings, opcode, packet_len, &known_formats)
            .unwrap_or((0, 0, 0));

    if let Some(known) = known_formats
        .iter()
        .find(|f| f.opcode == opcode && f.packet_len == packet_len && f.old_format)
    {
        let mut fmt = known.clone();
        fmt.guild_marker_offset = marker_offset;
        fmt.guild_flag_offset_from_marker = flag_rel;
        fmt.guild_string_offset_from_marker = guild_string_offset as isize - marker_offset as isize;
        return Ok(fmt);
    }

    if strings.len() < 5 {
        return Err(format!(
            "Representative packet has fewer than 5 strings (found {})",
            strings.len()
        ));
    }

    let known_new = known_formats
        .iter()
        .find(|f| f.opcode == opcode && f.packet_len == packet_len && !f.old_format);

    let guild_idx = if marker_offset > 0 {
        strings
            .iter()
            .enumerate()
            .position(|(_, (_, off))| *off == guild_string_offset)
            .unwrap_or(3)
    } else {
        3
    };

    // Build the ordered list of strings with the guild removed.
    // Expected layout: [enemy_char, friendly_char, friendly_family, enemy_guild, enemy_family]
    let mut ordered: Vec<(String, usize)> = Vec::new();
    for (idx, item) in strings.iter().enumerate() {
        if idx == guild_idx {
            continue;
        }
        ordered.push(item.clone());
    }

    if ordered.len() < 4 {
        return Err(format!(
            "Could not identify four character/family strings (found {})",
            ordered.len()
        ));
    }

    let mut enemy_char_offset = ordered[0].1;
    let mut friendly_char_offset = ordered[1].1;
    let mut friendly_family_offset = ordered[2].1;
    let mut enemy_family_offset = ordered[3].1;
    let guild_string_offset = strings[guild_idx].1;

    // If --name given, orient the friendly/enemy pairs using a packet that
    // actually contains the name. The format itself is derived from the most
    // common packet, so the offsets are the same.
    if let Some(ref name) = player_name {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let mut name_bytes = Vec::with_capacity(utf16.len() * 2);
        for &c in &utf16 {
            name_bytes.extend_from_slice(&c.to_le_bytes());
        }
        let pos = orient_packet
            .windows(name_bytes.len())
            .position(|w| w == name_bytes)
            .ok_or_else(|| format!("Player name '{}' not found in packet", name))?;

        if pos == enemy_char_offset {
            std::mem::swap(&mut friendly_char_offset, &mut enemy_char_offset);
            std::mem::swap(&mut friendly_family_offset, &mut enemy_family_offset);
        } else if pos != friendly_char_offset {
            return Err(format!(
                "Name '{}' not at a character offset (expected {} or {})",
                name, friendly_char_offset, enemy_char_offset
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
        guild_string_offset_from_marker: guild_string_offset as isize - marker_offset as isize,
        guild_string_offset: guild_string_offset,
        is_death_value: known_new.map(|k| k.is_death_value).unwrap_or(0),
        old_format: false,
    })
}

pub fn packet_format_path() -> std::path::PathBuf {
    std::path::PathBuf::from("packet_format.json")
}

/// Load known packet formats from an external `known_formats.json` file, falling
/// back to the embedded defaults shipped with the binary.
///
/// Searches, in order:
/// 1. The current working directory.
/// 2. The executable's directory.
/// 3. The embedded default (`rodent_logger_core/src/known_formats.json`).
pub fn load_known_formats() -> Vec<PacketFormat> {
    let candidates = [
        std::path::PathBuf::from("known_formats.json"),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .map(|p| p.join("known_formats.json"))
            .unwrap_or_default(),
    ];

    for path in &candidates {
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(json) => match serde_json::from_str::<Vec<PacketFormat>>(&json) {
                    Ok(formats) => return formats,
                    Err(e) => eprintln!(
                        "Warning: failed to parse known_formats.json at {}: {}. Using embedded defaults.",
                        path.display(),
                        e
                    ),
                },
                Err(e) => eprintln!(
                    "Warning: failed to read known_formats.json at {}: {}. Using embedded defaults.",
                    path.display(),
                    e
                ),
            }
        }
    }

    const DEFAULT_JSON: &str = include_str!("known_formats.json");
    serde_json::from_str(DEFAULT_JSON).unwrap_or_default()
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

/// Returns whether two formats describe the same packet layout.  The event
/// value is deliberately excluded: its meaning (which byte value is a death)
/// cannot be inferred from bytes alone and is preserved from a calibrated
/// format when a patch only moves fields around.
fn same_packet_layout(left: &PacketFormat, right: &PacketFormat) -> bool {
    left.opcode == right.opcode
        && left.packet_len == right.packet_len
        && left.enemy_char_offset == right.enemy_char_offset
        && left.enemy_family_offset == right.enemy_family_offset
        && left.friendly_char_offset == right.friendly_char_offset
        && left.friendly_family_offset == right.friendly_family_offset
        && left.guild_marker_offset == right.guild_marker_offset
        && left.guild_flag_offset_from_marker == right.guild_flag_offset_from_marker
        && left.guild_string_offset_from_marker == right.guild_string_offset_from_marker
        && left.guild_string_offset == right.guild_string_offset
        && left.old_format == right.old_format
}

/// Detect a layout in the current capture before export. This makes an
/// existing `packet_format.json` self-healing when a game patch changes an
/// opcode, packet size, or fixed string slot. The kill/death byte mapping is
/// retained for an updated layout because packet contents alone do not reveal
/// which semantic label belongs to `0` or `1`.
fn refresh_packet_formats(input: &str, formats: &mut Vec<PacketFormat>) -> Result<(), String> {
    let mut detected = match detect_format(input, None) {
        Ok(format) => format,
        Err(error) if formats.is_empty() => return Err(error),
        Err(_) => return Ok(()), // A capture without PvP events can still use saved formats.
    };

    if let Some(existing) = formats
        .iter()
        .find(|format| format.opcode == detected.opcode && format.packet_len == detected.packet_len)
    {
        // Keep the known event meaning and old-format behavior while replacing
        // only a layout that the current capture proves has moved.
        detected.is_death_value = existing.is_death_value;
        detected.old_format = existing.old_format;
        if same_packet_layout(existing, &detected) {
            return Ok(());
        }

        eprintln!(
            "Detected an updated layout for opcode 0x{:04X} ({} bytes); refreshing saved offsets.",
            detected.opcode, detected.packet_len
        );
    } else {
        eprintln!(
            "Detected a new event format: opcode 0x{:04X}, {} bytes. Saving it for future exports.",
            detected.opcode, detected.packet_len
        );
    }

    if let Some(position) = formats.iter().position(|format| {
        format.opcode == detected.opcode && format.packet_len == detected.packet_len
    }) {
        formats[position] = detected.clone();
    } else {
        formats.push(detected.clone());
    }
    save_all_packet_formats(formats)
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
    refresh_packet_formats(input, &mut formats).map_err(|error| {
        format!(
            "Could not detect packet format from pcap and no saved config found: {}",
            error
        )
    })?;

    let format_map: HashMap<(u16, usize), &PacketFormat> = formats
        .iter()
        .map(|f| ((f.opcode, f.packet_len), f))
        .collect();

    let mut cap =
        pcap::Capture::from_file(input).map_err(|e| format!("Failed to open pcap: {}", e))?;
    let mut wtr = Writer::from_path(output).map_err(|e| format!("Failed to create CSV: {}", e))?;

    wtr.write_record(&[
        "Timestamp",
        "Event",
        "Friendly Family",
        "Friendly Player",
        "Enemy Guild",
        "Enemy Player",
    ])
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
                                                is_death =
                                                    bdo_packet[flag_idx] == fmt.is_death_value;
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
                                    let enemy_name = if fmt.old_format {
                                        enemy_family.clone()
                                    } else {
                                        format!("{} ({})", enemy_family, enemy_char)
                                    };

                                    wtr.write_record(&[
                                        &ts,
                                        event_str,
                                        &friendly_family,
                                        &friendly_char,
                                        &enemy_guild,
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

        let (event, enemy_guild, player_1, player_2) = if record.len() == 5 {
            // Old: Timestamp, Event, Guild, Player 1, Player 2
            (
                record[1].to_string(),
                record[2].to_string(),
                record[3].to_string(),
                record[4].to_string(),
            )
        } else if record.len() >= 6 {
            // New: Timestamp, Event, Friendly Family, Friendly Player, Enemy Guild, Enemy Player
            (
                record[1].to_string(),
                record[4].to_string(),
                format!("{} ({})", record[2].trim(), record[3].trim()),
                record[5].to_string(),
            )
        } else {
            continue;
        };

        let is_death = event.to_lowercase() == "death";

        let p_stats = stats_map.entry(player_1.to_string()).or_default();
        if is_death {
            p_stats.deaths += 1;
        } else {
            p_stats.kills += 1;
        }

        let guild_key = if enemy_guild.trim().is_empty() {
            "No Guild".to_string()
        } else {
            enemy_guild.to_string()
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
        "Friendly Player", "Kills", "Deaths", "K/D"
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
            "Enemy Player", "Kills", "Deaths", "K/D"
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

#[cfg(test)]
mod tests {
    use super::find_all_bdo_strings;

    #[test]
    fn finds_utf16_names_with_spaces_and_unicode() {
        let mut payload = vec![0xAA, 0xBB, 0xCC];
        let expected = "Guild Árvore";
        for code_unit in expected.encode_utf16() {
            payload.extend_from_slice(&code_unit.to_le_bytes());
        }
        payload.extend_from_slice(&[0, 0]);

        assert_eq!(
            find_all_bdo_strings(&payload),
            vec![(expected.to_string(), 3)]
        );
    }
}
