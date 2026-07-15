use clap::{Parser, Subcommand};
use etherparse::{Ethernet2Header, Ipv4Header, TcpHeader};
use pcap::{Capture, Device};
use rodent_logger_core::{
    TcpState, calibrate_format, capture, detect_format, export_csv, find_all_bdo_strings,
    find_calibration_candidates, find_guild_marker, generate_stats, load_known_formats,
    load_packet_formats, packet_format_path, read_bdo_string, rodent_logger_dir,
    save_packet_format,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Parser)]
#[command(name = "bdo-sniffer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    List,
    Capture {
        interface: String,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(short, long)]
        filter: Option<String>,
    },
    Analyze {
        #[arg(short, long)]
        input: String,
    },
    ExportCsv {
        #[arg(short, long)]
        input: String,
        #[arg(short, long, default_value = "events.csv")]
        output: Option<String>,
    },
    Stats {
        #[arg(short, long)]
        input: String,
    },
    FindOpcode {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        name: String,
    },
    Detect {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        name: Option<String>,
    },
    DumpStrings {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        opcode: Option<u16>,
        #[arg(short, long)]
        packet_len: Option<usize>,
    },
    /// Calibrate a packet format from a known event. Use --interactive to pick
    /// strings interactively instead of passing all names as flags. Interactive
    /// mode requires 5 strings in the packet, so it does not support the old
    /// format (0x1AB2, 358 bytes) which omits the enemy character name.
    Calibrate {
        #[arg(short, long)]
        input: String,
        #[arg(long)]
        friendly_char: Option<String>,
        #[arg(long)]
        friendly_family: Option<String>,
        #[arg(long)]
        enemy_char: Option<String>,
        #[arg(long)]
        enemy_family: Option<String>,
        #[arg(long)]
        enemy_guild: Option<String>,
        #[arg(long)]
        event: Option<String>,
        #[arg(long, default_value_t = false)]
        interactive: bool,
    },
}

/// List all the available network connections.
fn list_interfaces() {
    println!("Available interfaces:");
    for device in Device::list().unwrap() {
        println!("  {} - {:?}", device.name, device.desc);
        for addr in &device.addresses {
            println!("    IP: {}", addr.addr);
        }
    }
}

// This is just for debuging, it does not matter for the general user
fn analyze(input: &str) {
    let mut cap = Capture::from_file(input).unwrap();

    while let Ok(packet) = cap.next_packet() {
        // Format the timestamp from the pcap header
        let ts = format!("{}.{}", packet.header.ts.tv_sec, packet.header.ts.tv_usec);

        // Parse the Ethernet header (first 14 bytes)
        if let Ok((eth, rest)) = Ethernet2Header::from_slice(packet.data) {
            // I only care about process IPv4 packets (skip ARP, IPv6, etc.)
            if eth.ether_type == etherparse::EtherType::IPV4 {
                // Parse the IPv4 header (next 20+ bytes)
                if let Ok((ipv4, rest)) = Ipv4Header::from_slice(rest) {
                    let src = Ipv4Addr::from(ipv4.source);
                    let dst = Ipv4Addr::from(ipv4.destination);

                    if ipv4.protocol == etherparse::IpNumber::TCP {
                        if let Ok((tcp, payload)) = TcpHeader::from_slice(rest) {
                            // Build a flag string like "AP" for ACK+PSH
                            let flags = format!(
                                "{}{}{}{}{}{}",
                                if tcp.syn { "S" } else { "" },
                                if tcp.ack { "A" } else { "" },
                                if tcp.psh { "P" } else { "" },
                                if tcp.fin { "F" } else { "" },
                                if tcp.rst { "R" } else { "" },
                                if tcp.urg { "U" } else { "" },
                            );

                            println!(
                                "{} | {}:{} -> {}:{} | {} | {} bytes payload",
                                ts,
                                src,
                                tcp.source_port,
                                dst,
                                tcp.destination_port,
                                flags,
                                payload.len()
                            );

                            if !payload.is_empty() {
                                println!("  Payload: {:02x?}", &payload[..payload.len().min(32)]);
                            }
                        }
                    }
                }
            }
        }
    }
}

// Helper to scan for the guild name dynamically by checking characters only
// Was using this on a earlier version but not being used at the moment, I'll keep it just in case.
fn find_bdo_string_in_range(
    payload: &[u8],
    start_range: usize,
    end_range: usize,
) -> (String, usize) {
    for start in start_range..=end_range {
        if start + 2 <= payload.len() {
            // Look for a valid ASCII character in UTF-16 (printable character, next byte is 0)
            if payload[start] >= 0x20 && payload[start] <= 0x7E && payload[start + 1] == 0x00 {
                let candidate = read_bdo_string(payload, start);
                let cand_len = candidate.len();

                if cand_len >= 3 && cand_len <= 30 {
                    let is_valid = candidate.chars().all(|c| {
                        c.is_alphanumeric() || c.is_whitespace() || c.is_ascii_punctuation()
                    });
                    if is_valid {
                        return (candidate, start);
                    }
                }
            }
        }
    }
    (String::new(), 0)
}

// Helper function I made so I don't have to manualy look into hex data for the new Opcode for a
// kill event, wouldn't be an issue if it didn't change every other patch.
fn find_opcode(input: &str, target_name: &str) {
    let mut cap = pcap::Capture::from_file(input).unwrap();
    let mut streams: HashMap<(IpAddr, u16, IpAddr, u16), TcpState> = HashMap::new();

    // Convert target name to UTF-16 Little-Endian raw bytes
    let target_utf16: Vec<u16> = target_name.encode_utf16().collect();
    let mut target_bytes = Vec::with_capacity(target_utf16.len() * 2);
    for &c in &target_utf16 {
        target_bytes.extend_from_slice(&c.to_le_bytes());
    }

    let mut found_opcodes: HashMap<(u16, usize), u32> = HashMap::new();

    println!(
        "Scanning PCAP for UTF-16 string '{}' to discover NW Opcode...",
        target_name
    );

    while let Ok(packet) = cap.next_packet() {
        if let Ok(headers) = etherparse::PacketHeaders::from_ethernet_slice(packet.data) {
            if let Some(ip_header) = headers.net {
                let (src_ip, dst_ip) = match ip_header {
                    etherparse::NetHeaders::Ipv4(ipv4, _) => (
                        IpAddr::V4(Ipv4Addr::from(ipv4.source)),
                        IpAddr::V4(Ipv4Addr::from(ipv4.destination)),
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
                        if !payload.is_empty() {
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
                                        let p_len = u16::from_le_bytes([
                                            state.buffer[i],
                                            state.buffer[i + 1],
                                        ])
                                            as usize;
                                        // Look for any plausible unencrypted packet between 300-400 bytes
                                        if p_len >= 300
                                            && p_len <= 400
                                            && state.buffer[i + 2] == 0x00
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

                                // Only search inside unencrypted packets sized like a PvP Broadcast (300 to 400 bytes)
                                if is_unencrypted && packet_len >= 300 && packet_len <= 400 {
                                    // Search for the UTF-16 byte sequence of the given name
                                    if bdo_packet
                                        .windows(target_bytes.len())
                                        .any(|window| window == target_bytes)
                                    {
                                        let count =
                                            found_opcodes.entry((opcode, packet_len)).or_insert(0);
                                        *count += 1;
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
    }

    println!("\nScan Complete! Found the following candidate opcodes:");
    println!("---------------------------------------------------------");
    for ((opcode, len), occ) in found_opcodes {
        println!(
            "Opcode: 0x{:04X} | Packet Length: {} bytes | Occurrences: {}",
            opcode, len, occ
        );
    }
    println!("---------------------------------------------------------");
    println!(
        "Look for the opcode with the highest occurrences. Update the NW_OPCODE const in your code to match!"
    );
}

fn prompt_usize(prompt: &str, max: usize) -> Option<usize> {
    use std::io;
    loop {
        print!("{} (or 'q' to quit): ", prompt.trim_end());
        let _ = io::Write::flush(&mut io::stdout());
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            continue;
        }
        let trimmed = input.trim();
        if trimmed == "q" || trimmed == "Q" {
            return None;
        }
        match trimmed.parse::<usize>() {
            Ok(n) if n >= 1 && n <= max => return Some(n),
            _ => println!("Please enter a number between 1 and {}", max),
        }
    }
}

fn prompt_event() -> Option<String> {
    use std::io;
    loop {
        print!("Event type (kill/death, or 'q' to quit): ");
        let _ = io::Write::flush(&mut io::stdout());
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            continue;
        }
        let trimmed = input.trim();
        if trimmed == "q" || trimmed == "Q" {
            return None;
        }
        let lowered = trimmed.to_lowercase();
        if lowered == "kill" || lowered == "death" {
            return Some(lowered);
        }
        println!("Please enter 'kill' or 'death'");
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::List => {
            println!("Available interfaces:");
            for device in Device::list().unwrap() {
                println!("  {} - {:?}", device.name, device.desc);
                for addr in &device.addresses {
                    println!("    IP: {}", addr.addr);
                }
            }
        }
        Commands::Capture {
            interface,
            output,
            filter,
        } => {
            let pcap_dir = rodent_logger_dir("pcap");
            let filename = output.unwrap_or_else(|| {
                let now = chrono::Local::now();
                format!("bdo_capture_{}.pcap", now.format("%Y%m%d_%H%M%S"))
            });
            let output = pcap_dir.join(filename).to_string_lossy().to_string();
            let running = Arc::new(AtomicBool::new(true));
            let r = running.clone();
            ctrlc::set_handler(move || {
                println!("\nReceived Ctrl+C, shutting down gracefully...");
                r.store(false, Ordering::SeqCst);
            })
            .expect("Error setting Ctrl+C handler");
            let progress = AtomicU64::new(0);
            match capture(&interface, &output, filter.as_deref(), running, &progress) {
                Ok(count) => println!("\nCapture complete. {} packets saved to {}", count, output),
                Err(e) => eprintln!("Capture error: {}", e),
            }
        }
        Commands::Analyze { input } => {
            analyze(&input);
        }
        Commands::ExportCsv { input, output } => {
            let csv_dir = rodent_logger_dir("csv");
            let filename = output.unwrap_or_else(|| "events.csv".to_string());
            let out_file = csv_dir.join(filename).to_string_lossy().to_string();
            match export_csv(&input, &out_file) {
                Ok(count) => println!("Successfully exported {} events to {}", count, out_file),
                Err(e) => eprintln!("Export error: {}", e),
            }
        }
        Commands::Stats { input } => {
            println!("{}", generate_stats(&input));
        }
        Commands::FindOpcode { input, name } => find_opcode(&input, &name),
        Commands::Detect { input, name } => match detect_format(&input, name.as_deref()) {
            Ok(fmt) => {
                println!("Detected packet format:");
                println!("  Opcode: 0x{:04X}", fmt.opcode);
                println!("  Packet length: {} bytes", fmt.packet_len);
                println!("  Enemy char offset: {}", fmt.enemy_char_offset);
                println!("  Enemy family offset: {}", fmt.enemy_family_offset);
                println!("  Friendly char offset: {}", fmt.friendly_char_offset);
                println!("  Friendly family offset: {}", fmt.friendly_family_offset);
                println!("  Guild marker offset: {}", fmt.guild_marker_offset);
                println!(
                    "  Guild flag offset rel: {:+}",
                    fmt.guild_flag_offset_from_marker
                );
                println!(
                    "  Guild string offset rel: {:+}",
                    fmt.guild_string_offset_from_marker
                );

                match save_packet_format(&fmt) {
                    Ok(()) => println!("\nSaved to {}", packet_format_path().display()),
                    Err(e) => eprintln!("\nFailed to save: {}", e),
                }
            }
            Err(e) => eprintln!("Detection failed: {}", e),
        },
        Commands::Calibrate {
            input,
            friendly_char,
            friendly_family,
            enemy_char,
            enemy_family,
            enemy_guild,
            event,
            interactive,
        } => {
            let (friendly_char, friendly_family, enemy_char, enemy_family, enemy_guild, event) =
                if interactive {
                    let (opcode, packet_len, ts, strings) =
                        match find_calibration_candidates(&input) {
                            Ok(v) => v,
                            Err(e) => {
                                eprintln!("Calibration failed: {}", e);
                                return;
                            }
                        };

                    println!(
                        "Found packet format 0x{:04X} ({} bytes) at timestamp {}",
                        opcode, packet_len, ts
                    );
                    println!("Strings found in a representative packet:");
                    for (idx, (s, off)) in strings.iter().enumerate() {
                        println!("  [{}] offset {:>3}: {}", idx + 1, off, s);
                    }
                    println!();

                    let Some(friendly_char_idx) =
                        prompt_usize("Friendly character (char name) index", strings.len())
                    else {
                        return;
                    };
                    let Some(friendly_family_idx) =
                        prompt_usize("Friendly family index", strings.len())
                    else {
                        return;
                    };
                    let Some(enemy_char_idx) =
                        prompt_usize("Enemy character (char name) index", strings.len())
                    else {
                        return;
                    };
                    let Some(enemy_family_idx) = prompt_usize("Enemy family index", strings.len())
                    else {
                        return;
                    };
                    let Some(enemy_guild_idx) = prompt_usize("Enemy guild index", strings.len())
                    else {
                        return;
                    };

                    let indices = [
                        friendly_char_idx,
                        friendly_family_idx,
                        enemy_char_idx,
                        enemy_family_idx,
                        enemy_guild_idx,
                    ];
                    if indices
                        .iter()
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                        != 5
                    {
                        eprintln!("Calibration failed: each selected string must be different");
                        return;
                    }

                    let Some(event_str) = prompt_event() else {
                        return;
                    };

                    (
                        strings[friendly_char_idx - 1].0.clone(),
                        strings[friendly_family_idx - 1].0.clone(),
                        strings[enemy_char_idx - 1].0.clone(),
                        strings[enemy_family_idx - 1].0.clone(),
                        strings[enemy_guild_idx - 1].0.clone(),
                        event_str,
                    )
                } else {
                    match (
                        friendly_char,
                        friendly_family,
                        enemy_char,
                        enemy_family,
                        enemy_guild,
                        event,
                    ) {
                        (Some(fc), Some(ff), Some(ec), Some(ef), Some(eg), Some(ev)) => {
                            (fc, ff, ec, ef, eg, ev)
                        }
                        _ => {
                            eprintln!(
                                "Calibration failed: provide all string flags or use --interactive"
                            );
                            return;
                        }
                    }
                };

            match calibrate_format(
                &input,
                &friendly_char,
                &friendly_family,
                &enemy_char,
                &enemy_family,
                &enemy_guild,
                &event,
            ) {
                Ok(fmt) => {
                    println!("Calibrated packet format:");
                    println!("  Opcode: 0x{:04X}", fmt.opcode);
                    println!("  Packet length: {} bytes", fmt.packet_len);
                    println!("  Friendly char offset: {}", fmt.friendly_char_offset);
                    println!("  Friendly family offset: {}", fmt.friendly_family_offset);
                    println!("  Enemy char offset: {}", fmt.enemy_char_offset);
                    println!("  Enemy family offset: {}", fmt.enemy_family_offset);
                    println!("  Enemy guild offset: {}", fmt.guild_string_offset);
                    println!("  Guild marker offset: {}", fmt.guild_marker_offset);
                    println!(
                        "  Guild flag offset rel: {:+}",
                        fmt.guild_flag_offset_from_marker
                    );
                    println!(
                        "  Guild string offset rel: {:+}",
                        fmt.guild_string_offset_from_marker
                    );
                    println!("  Is death value: {}", fmt.is_death_value);

                    // Append to known_formats.json in the current directory.
                    let path = std::path::PathBuf::from("known_formats.json");
                    let mut formats = if path.exists() {
                        match std::fs::read_to_string(&path) {
                            Ok(json) => serde_json::from_str::<Vec<_>>(&json)
                                .unwrap_or_else(|_| load_known_formats()),
                            Err(_) => load_known_formats(),
                        }
                    } else {
                        load_known_formats()
                    };
                    formats.retain(|f| !(f.opcode == fmt.opcode && f.packet_len == fmt.packet_len));
                    formats.push(fmt.clone());
                    match serde_json::to_string_pretty(&formats) {
                        Ok(json) => match std::fs::write(&path, json) {
                            Ok(()) => println!("\nSaved to {}", path.display()),
                            Err(e) => eprintln!("\nFailed to save: {}", e),
                        },
                        Err(e) => eprintln!("\nFailed to serialize format: {}", e),
                    }
                }
                Err(e) => eprintln!("Calibration failed: {}", e),
            }
        }
        Commands::DumpStrings {
            input,
            opcode,
            packet_len,
        } => {
            let fmt = load_packet_formats();
            let target = opcode
                .zip(packet_len)
                .or_else(|| fmt.last().map(|f| (f.opcode, f.packet_len)));

            let (target_opcode, target_len) = match target {
                Some((op, len)) => (op, len),
                None => {
                    eprintln!("No saved format and no --opcode/--packet-len provided");
                    return;
                }
            };
            let mut dumped = 0;

            let mut cap = match pcap::Capture::from_file(&input) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to open pcap: {}", e);
                    return;
                }
            };
            let mut streams: HashMap<(IpAddr, u16, IpAddr, u16), TcpState> = HashMap::new();

            while let Ok(packet) = cap.next_packet() {
                if let Ok(headers) = etherparse::PacketHeaders::from_ethernet_slice(packet.data) {
                    if let Some(transport) = headers.transport {
                        if let etherparse::TransportHeader::Tcp(tcp) = transport {
                            let payload = headers.payload.slice();
                            if payload.is_empty() {
                                continue;
                            }

                            let src_ip = match headers.net.as_ref().unwrap() {
                                etherparse::NetHeaders::Ipv4(ipv4, _) => {
                                    IpAddr::V4(Ipv4Addr::from(ipv4.source))
                                }
                                etherparse::NetHeaders::Ipv6(ipv6, _) => {
                                    IpAddr::V6(std::net::Ipv6Addr::from(ipv6.source))
                                }
                                etherparse::NetHeaders::Arp(_) => continue,
                            };
                            let dst_ip = match headers.net.as_ref().unwrap() {
                                etherparse::NetHeaders::Ipv4(ipv4, _) => {
                                    IpAddr::V4(Ipv4Addr::from(ipv4.destination))
                                }
                                etherparse::NetHeaders::Ipv6(ipv6, _) => {
                                    IpAddr::V6(std::net::Ipv6Addr::from(ipv6.destination))
                                }
                                etherparse::NetHeaders::Arp(_) => continue,
                            };
                            let key = (src_ip, tcp.source_port, dst_ip, tcp.destination_port);
                            let state = streams.entry(key).or_insert(TcpState {
                                buffer: Vec::new(),
                                next_seq: tcp.sequence_number,
                            });

                            let seq = tcp.sequence_number;
                            let payload_len = payload.len() as u32;
                            if seq == state.next_seq {
                                state.buffer.extend_from_slice(payload);
                                state.next_seq = seq.wrapping_add(payload_len);
                            } else {
                                state.buffer.clear();
                                state.buffer.extend_from_slice(payload);
                                state.next_seq = seq.wrapping_add(payload_len);
                            }

                            let mut offset = 0;
                            while offset + 5 <= state.buffer.len() {
                                let p_len = u16::from_le_bytes([
                                    state.buffer[offset],
                                    state.buffer[offset + 1],
                                ]) as usize;
                                if p_len < 5 || p_len > 1000 {
                                    offset += 1;
                                    continue;
                                }
                                if offset + p_len > state.buffer.len() {
                                    break;
                                }

                                let bdo_packet = &state.buffer[offset..offset + p_len];
                                let is_unencrypted = bdo_packet[2] == 0x00;
                                let opcode_val = u16::from_le_bytes([bdo_packet[3], bdo_packet[4]]);

                                if is_unencrypted
                                    && opcode_val == target_opcode
                                    && p_len == target_len
                                {
                                    let strings = find_all_bdo_strings(bdo_packet);
                                    let known_formats = load_known_formats();
                                    let guild = find_guild_marker(
                                        bdo_packet,
                                        &strings,
                                        opcode_val,
                                        p_len,
                                        &known_formats,
                                    );
                                    dumped += 1;

                                    println!("Found matching packet ({} bytes):\n", p_len);
                                    println!("--- All BDO strings by offset ---");
                                    for (s, off) in &strings {
                                        println!("  {:>4}: \"{}\"", off, s);
                                    }

                                    if let Some((gm_off, flag_rel, guild_rel)) = guild {
                                        let guild_off = gm_off + guild_rel as usize;
                                        println!("\n--- Guild marker ---");
                                        println!("  Marker at offset: {}", gm_off);
                                        println!(
                                            "  Flag rel: {:+} -> byte {}",
                                            flag_rel,
                                            if flag_rel >= 0 {
                                                gm_off + flag_rel as usize
                                            } else {
                                                gm_off.saturating_sub((-flag_rel) as usize)
                                            }
                                        );
                                        println!(
                                            "  Guild string rel: {:+} -> byte {} -> \"{}\"",
                                            guild_rel,
                                            guild_off,
                                            read_bdo_string(bdo_packet, guild_off)
                                        );
                                        println!(
                                            "\n--- Raw bytes around marker (offset {}) ---",
                                            gm_off
                                        );
                                        let start = gm_off.saturating_sub(8);
                                        let end = (gm_off + 20).min(bdo_packet.len());
                                        for i in start..end {
                                            print!("{:02x} ", bdo_packet[i]);
                                            if (i - start + 1) % 16 == 0 {
                                                println!();
                                            }
                                        }
                                        println!();
                                    } else {
                                        println!("\nNo guild marker found");
                                    }

                                    println!();
                                    // Stop after dumping the first 5 matching packets
                                    if dumped >= 5 {
                                        return;
                                    }
                                }
                                offset += p_len;
                            }

                            if offset > 0 {
                                state.buffer.drain(0..offset);
                            }
                        }
                    }
                }
            }
            eprintln!("No matching packet found");
        }
    }
}
