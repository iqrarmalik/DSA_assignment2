# Packet Capture and Replay Tool

A high-performance C++ application designed to **capture**, **analyze**, and **replay** network packets from live interfaces or `.pcap` files.
It uses multithreading and efficient data structures to handle real-time network data processing and simulation.

## 🚀 Features
- 🧠 Layered Packet Parsing (Ethernet, IP, TCP, UDP)
- 🧩 Threaded Architecture (independent loops for capture, parse, replay)
- ⏱️ Real-Time Replay preserving original timing
- 📂 PCAP file input/output support
- 🧵 Thread-safe shared packet buffers
- ⚡ Efficient design for high-rate capture and replay

## 🛠️ Requirements
| Dependency | Description |
|-------------|-------------|
| C++17 or later | Required for threading and filesystem support |
| libpcap | For live packet capture and `.pcap` file parsing |
| pthread | For multithreading support |
| g++ | Recommended compiler |

## ⚙️ Build Instructions

### Linux / macOS
```bash
sudo apt install g++ libpcap-dev -y
git clone https://github.com/yourusername/packet-capture-replay.git
cd packet-capture-replay
g++ main.cpp -o packet-replay -lpcap -lpthread -O2
```

## ▶️ Usage
### Capture Live Packets
```bash
sudo ./packet-replay --capture eth0
```
### Replay from PCAP File
```bash
sudo ./packet-replay --replay capture.pcap
```

## ⚠️ Notes
- Root privileges required for live capture.
- Enable promiscuous mode for full network visibility.
- Tune constants like `OVERSIZE_LIMIT` for performance.

## 💡 Future Improvements
- REST API control
- IPv6 and custom protocol support
- GUI Dashboard
- Real-time traffic statistics

## 📜 License
Licensed under the **MIT License**.
