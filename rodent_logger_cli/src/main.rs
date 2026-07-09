use clap::{Parser, Subcommand};
use etherparse::{Ethernet2Header, Ipv4Header, TcpHeader};
use pcap::{Capture, Device};
use rodent_logger_core::{TcpState, capture, export_csv, generate_stats, read_bdo_string, rodent_logger_dir};
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
    }
}
