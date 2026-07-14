# BDO PvP Packet Sniffer & Stats Logger

A high-performance, Rust-based packet sniffer and offline PCAP analyzer for Black Desert Online (BDO). This tool reconstructs TCP streams to extract PvP matchup data (Kills, Deaths, Guilds, and Players) during Node Wars and Sieges, generating clean CSV logs and comprehensive K/D statistics.

## Features

* **Live Capture:** Record BDO network traffic directly to a `.pcap` file.
* **Offline Analysis:** Parse saved `.pcap` files and export events to CSV.
* **K/D Tracking:** Generate full K/D stats for allied players and enemy players grouped by guild.
* **Auto Format Detection:** Automatically detects the current BDO packet format and caches it in `packet_format.json`.
* **Opcode/Format Helpers:** Built-in commands to discover opcodes and inspect packet strings when the game format changes.

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
cargo build    # CLI only
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
It will save a pcap file with the format `bdo_capture_<date>_<time>.pcap`, or you can use `-o` to specify a custom name. Use `-f` to provide a capture filter.

```bash
rodent_logger capture <INTERFACE_NAME> -f "tcp portrange 8888-9993"
```

### 3. Detect Packet Format

When BDO patches change the packet layout, run `detect` to discover the current format. The result is saved to `packet_format.json` and used automatically by `export-csv`.

```bash
rodent_logger detect -i my_nodewar.pcap
```

Optionally provide your own family name to help resolve friendly/enemy orientation:

```bash
rodent_logger detect -i my_nodewar.pcap -n MyFamilyName
```

### 4. Export to CSV

Parse your saved `.pcap` file, reconstruct the TCP streams, extract the PvP matchups, and export them to a clean CSV file. If no `packet_format.json` exists, the tool will attempt to auto-detect the format first.

```bash
rodent_logger export-csv -i my_nodewar.pcap -o events.csv
```

**CSV Format Output:**
`Timestamp | Event (Kill/Death) | Enemy Guild | Friendly Player | Enemy Player`

**Example `events.csv`:**

```csv
Timestamp,Event,Guild,Player 1,Player 2
1720456789.123456,Kill,EnemyGuild,Smith (Guardian),Jones (Wizard)
1720456790.234567,Death,EnemyGuild,Smith (Guardian),Jones (Wizard)
1720456791.345678,Kill,AnotherGuild,Doe (Lahn),Brown (Warrior)
1720456792.456789,Kill,EnemyGuild,Smith (Guardian),Davis (Ranger)
```

### 5. View K/D Statistics

Instantly generate K/D summary tables directly in your terminal from your exported CSV. Displays individual allied stats, enemy guild stats, enemy player stats per guild, and overall alliance totals.

```bash
rodent_logger stats -i events.csv
```

**Example `stats` output:**

```text
================ Allied K/D Summary (Players: 3) ================
Family (Character)                  | Kills  | Deaths | K/D
----------------------------------------------------
Smith (Guardian)                    | 12     | 4      | 3.00
Doe (Lahn)                          | 8      | 6      | 1.33
Johnson (Mystic)                    | 5      | 7      | 0.71
====================================================

================ Enemy Player K/D Per Guild ================
--- EnemyGuild (Players: 3, K: 11 D: 20 K/D: 0.55) ---
  Family (Character)                  | Kills  | Deaths | K/D
  Jones (Wizard)                        | 4      | 5      | 0.80
  Davis (Ranger)                      | 3      | 7      | 0.43
  Miller (Sorceress)                  | 4      | 8      | 0.50

--- AnotherGuild (Players: 1, K: 3 D: 5 K/D: 0.60) ---
  Family (Character)                  | Kills  | Deaths | K/D
  Brown (Warrior)                     | 3      | 5      | 0.60

==========================================================

================ Enemy Guild K/D Summary ================
Guild Name                          | Players | Kills  | Deaths | K/D
-----------------------------------------------------------------
EnemyGuild                          | 3       | 11     | 20     | 0.55
AnotherGuild                        | 1       | 3      | 5      | 0.60
=========================================================

================ Overall Team Stats ================
Team                | Kills  | Deaths | K/D
----------------------------------------------------
Allies (Alliance)   | 25     | 17     | 1.47
Enemies             | 17     | 25     | 0.68
====================================================
```

### 6. Find Opcode (Dev/Debug)

If kills/deaths are no longer being exported after a patch, use a known player name to discover the new opcode for the PvP broadcast packet.

```bash
rodent_logger find-opcode -i my_nodewar.pcap -n KnownPlayerName
```

### 7. Dump Strings (Dev/Debug)

Dump all readable strings from packets matching a saved format. Useful for inspecting packet contents when debugging format detection.

```bash
rodent_logger dump-strings -i my_nodewar.pcap
```

You can also override the opcode and packet length:

```bash
rodent_logger dump-strings -i my_nodewar.pcap -o 0x1CD6 -p 392
```

### 8. Analyze (Debug)

Print a raw summary of every TCP packet in the pcap (timestamp, IPs, ports, flags, payload size). This is a low-level debugging command.

```bash
rodent_logger analyze -i my_nodewar.pcap
```

## Troubleshooting

### `export-csv` fails with "Could not detect packet format"

The game format may have changed, or the pcap does not contain enough data. Run `detect` manually with your character name:

```bash
rodent_logger detect -i my_nodewar.pcap -n MyFamilyName
```

Then re-run `export-csv`.

### Kills/Deaths look swapped or guilds are wrong

Delete `packet_format.json` and re-run `detect` with your character name to reorient friendly/enemy fields:

```bash
rm packet_format.json
rodent_logger detect -i my_nodewar.pcap -n MyFamilyName
```

### No events after a patch

Use `find-opcode` with a known player name to discover the new opcode, then update or regenerate `packet_format.json` with `detect`.

## License

This project is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you shall be dual licensed as above, without any additional terms or conditions.

## Disclaimer

This tool passively analyzes raw network packets and does not hook into, inject, or modify the Black Desert Online game client in any way. However, the use of packet sniffers may violate the Terms of Service of the game. **Use this tool at your own risk.**
