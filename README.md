# Ghost Beacon

A WiFi Probe Request Sniffer and Visualizer using an ESP32 and a WS2812 RGB LED Ring.

## Features
- Captures Probe Requests.
- Visualizes devices on a 24-LED Ring.
- Configurable via Cyberpunk Web Interface.
- Deauth Detector (Red Alarm).
- Channel Hopping (1-13).
- Export logs to CSV.

## Hardware
- ESP32
- WS2812B Ring (24 LEDs, Data Pin GPIO 16)
- 5V Power Supply

## Installation
1. Upload `GhostBeacon.ino` to ESP32.
2. Connect to WiFi `GHOST_BEACON`.
3. Password: `GhostGetConf34`.
4. Open browser at `http://192.168.4.1`.
5. Configure Date/Time and Add Devices.

## Usage
The ring is OFF by default. It lights up when a device is detected.
- Unknown devices: Random color (3s).
- Known devices: Configured color (30s).
- Deauth: Fast Red Blink (30s).

## License
Educational use only.

