# OSPF & BGP Route Monitor

A C-based network protocol analysis tool that reads PCAP packet captures, identifies OSPF and BGP messages, tracks route announcements and withdrawals, and detects selected routing events and anomalies. A Streamlit dashboard displays metrics and event history from the generated log file.

## Features

- Packet capture analysis using C and libpcap
- OSPF message detection and Link-State Advertisement (LSA) inspection
- BGP message classification, including OPEN, UPDATE, and NOTIFICATION
- IPv4 prefix announcement and withdrawal tracking
- Logging of routing events and selected anomaly alerts
- Streamlit dashboard with metrics, event trends, prefix tracking, and event search

## Technologies

- C
- libpcap
- Python
- Scapy
- Streamlit
- Pandas
- PCAP packet captures

## Project Files

- `main.c` — packet analyzer and event logger
- `generate_test_pcap.py` — generates synthetic packets for testing
- `dashboard.py` — dashboard for viewing logged events
- `test_capture.pcap` — generated test packet capture
- `route_monitor.log` — analyzer event log

## Requirements

- GCC
- libpcap development headers
- Python 3
- Python packages: Scapy, Streamlit, and Pandas

## Run the Project

### 1. Compile the C analyzer

```bash
gcc -D_DEFAULT_SOURCE -include sys/types.h -Wall -Wextra -std=c11 main.c -o route_monitor -lpcap
```

### 2. Generate test packets

Activate your Python virtual environment, install the required packages if needed, and run:

```bash
python3 generate_test_pcap.py
```

### 3. Analyze the capture

```bash
./route_monitor test_capture.pcap
```

### 4. Launch the dashboard

In the project directory, activate the virtual environment if needed and run:

```bash
streamlit run dashboard.py
```

Open the local URL printed by Streamlit in your browser.

## Testing

The synthetic test capture is designed to exercise OSPF and BGP message handling, route announcements and withdrawals, and BGP notification alerts. The analyzer output and dashboard log should be checked against the expected test events.

## Limitations

The current version analyzes saved PCAP files and displays saved log events. It is not a live network packet-capture service or a production-grade routing daemon. Test results depend on the packet formats implemented by the analyzer.

## Future Improvements

- Improve validation of BGP UPDATE and IPv4 prefix parsing
- Improve event-chart presentation for captures with closely spaced timestamps
- Add more automated tests for malformed packets and routing anomalies
- Explore live capture and monitoring integrations
