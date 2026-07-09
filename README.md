# BDO PvP Packet Sniffer & Stats Logger

A high-performance, Rust-based packet sniffer and offline PCAP analyzer for Black Desert Online (BDO). This tool reconstructs TCP streams to extract absolute PvP Matchup data (Kills, Deaths, Guilds, and 3D World Coordinates) during Node Wars and Sieges, generating clean CSV logs and comprehensive K/D statistics.

## Features

* **K/D Tracking:** Reads the pcap file and displays full K/D stats of each member and Guild/Ally vs. Enemy.
* **Planned:** Individual enemy player K/D tracking, per-class stats, and other improvements.

## Prerequisites

To run this project, you need the appropriate PCAP packet capture library installed on your system:

* **Windows:** Install [Npcap](https://npcap.com/) (Make sure to check "Install Npcap in WinPcap API-compatible Mode" during installation).
* **Linux (Debian/Ubuntu):** `sudo apt-get install libpcap-dev`
* **Linux (Arch based):** `sudo pacman -S libpcap`
* **macOS:** `brew install libpcap`

## Building from Source

```bash
git clone https://github.com/your-username/rodent_logger.git
cd rodent_logger
cargo build    # CLI only (fast)
```

For the full workspace (including GUI): `cargo build --workspace`

## Usage

The CLI is structured into modular commands. Open your terminal (Command Prompt, PowerShell, or Bash) in the folder where the executable is located to run these commands.

*(Note: In the examples below, Windows users should use `rodent_logger.exe`, while Linux/Mac users should use `./rodent_logger`)*

Files are saved to `~/Documents/rodent_logger/{pcap,csv}` by default.

### 1. List Network Interfaces

Find the name of your active network adapter (or VPN virtual adapter if using ExitLag/Mudfish):

```bash
rodent_logger list
```

### 2. Capture Live Traffic

Record live Node War traffic to a `.pcap` file. Press `Ctrl+C` to cleanly stop and save the capture.
It will save a pcap file with the format bdo_capture_date_time.pcap or you can use -o and give it a custom name.

```bash
rodent_logger capture <INTERFACE_NAME> "tcp portrange 8888-9993"
```

### 3. Export to CSV

Parse your saved `.pcap` file, reconstruct the TCP streams, extract the exact PvP matchups, and export them to a clean CSV file.

```bash
rodent_logger export-csv -i my_nodewar.pcap -o events.csv
```

**CSV Format Output:**
`Timestamp | Event (Kill/Death) | Enemy Guild | Friendly Player | Enemy Player`

### 4. View K/D Statistics

Instantly generate K/D summary tables directly in your terminal from your exported CSV. Displays individual allied stats, enemy guild stats, and overall alliance totals.

```bash
rodent_logger stats -i events.csv
```

## Disclaimer

This tool passively analyzes raw network packets and does not hook into, inject, or modify the Black Desert Online game client in any way. However, the use of packet sniffers may violate the Terms of Service of the game. **Use this tool at your own risk.**
