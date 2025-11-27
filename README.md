# protofire
protofire is a modular, multi-protocol fuzzer targeting Industrial Control System (ICS) and Operational Technology (OT) protocols. Designed for red team operators, fuzzing researchers, and security engineers working with ICS/SCADA environments.

**Status: Alpha**

> `protofire` is in **alpha** — use at your own risk. Expect bugs, instability, and rapid changes.  
> Ideal for **red team experiments**, and **industrial protocol research**.

![status: alpha](https://img.shields.io/badge/status-alpha-orange)


## Features
- Modular plugin-based protocol fuzzing
  - Supports:
    - Modbus/TCP
    - DNP3
    - S7comm
    - IEC 60870-5-104
    - OPC UA
- Mutation strategies:
  - Random bit flipping
  - Overflow injection
  - Dictionary-based input
  - Format string injection
  - Type confusion
  - Time-based values
  - Sequence violations
- PCAP input/output support
- Stateful fuzzing (e.g., tracking transaction/session IDs)
- Multi-threaded fuzzing engine
- Replay mode from PCAP files
- Anomaly, crash, and timeout logging

## Architecture Overview
```
protofire/
├── fuzzer.c                  # Main logic, CLI interface, and thread controller
├── fuzzer_protocol.h         # Protocol module interface definition
├── fuzzer_protocol_common.c # Common utilities for all protocol handlers
├── grammar_fieldmap.h        # Field mapping stub for future grammar-based mutations
├── plugins/
│   ├── modbus_module.c       # Modbus fuzzing plugin
│   ├── dnp3_module.c         # DNP3 fuzzing plugin
│   ├── s7comm_module.c       # Siemens S7Comm fuzzing plugin
│   ├── iec104_module.c       # IEC 60870-5-104 fuzzing plugin
│   ├── opc_ua_module.c       # OPC UA fuzzing plugin
├── crashes/                  # Saved payloads that triggered crashes
├── logs/                     # Execution and error logging
├── Makefile                  # Build automation script
├── protofire                 # Compiled fuzzer binary (output)
└── README.md                 # Project documentation
```
Build Instructions

Dependencies:
- gcc
- libpcap-dev
- make
- pthread

To build everything:
```bash
make
```
Usage
```bash
./protofire -t <IP> -P <PORT> -p <protocol> [options]
```
### Command-Line Options

```
  -t <ip>             Target IP address

  -P <port>           Target port (optional, auto-set based on protocol)

  -p <protocol>       Protocol to fuzz:
                        modbus, dnp3, s7, iec104, opcua

  -s <strategy>       Mutation strategy:
                        random, bitflip, overflow, dictionary,
                        format, type, time, sequence

  -i <iterations>     Number of fuzzing iterations

  -T <threads>        Number of threads to use

  -S                  Enable stateful fuzzing (e.g., session tracking)

  -R <file.pcap>      Record all sent packets to a PCAP file

  -r <file.pcap>      Replay packets from an existing PCAP

  -d <ms>             Delay (in milliseconds) between packets

  -v                  Enable verbose logging
```
Example:
```bash
./protofire -t 192.168.1.10 -p modbus -s dictionary -i 5000 -T 8 -R fuzz_run.pcap
```
### Fuzzing Strategies

```
random     – random byte mutations

bitflip    – single-bit flips

overflow   – fill fields with 0xFF (overflow testing)

dictionary – inject protocol-specific invalid codes and edge-case values

format     – format string injection (e.g., %x%n, %s)

type       – type confusion between float and int

time       – inject maximum timestamp values (e.g., 0xFFFFFFFFFFFFFFFF)

sequence   – force protocol into out-of-order or invalid state transitions
```
### Protocol Coverage

Modbus/TCP
- Mutation of function codes and quantity fields
- Handles MBAP header length recalculation

DNP3
- Field flips and CRC recalculation
- Field size-aware mutation

S7comm
- Mutation of PDU fields and protocol identifiers

IEC 60870-5-104
- ASDU type mutation and checksum recalculation

OPC UA
- Mutation of headers and message types
- Includes format string injection potential

### Output Logging
- logs/ contains runtime logs and anomaly detection
- crashes/ contains payloads that triggered unexpected behavior
- If -R is enabled, PCAP output is saved

### Replay Mode

You can fuzz by mutating captured traffic using:  
```bash
./protofire -r input.pcap -t 192.168.1.100 -p modbus -s bitflip
```
This enables a semi-black-box fuzzing strategy using prior traffic.

### Extending Protocols

To add a new protocol:
1. Create a new plugin source file plugins/newproto_module.c
2. Implement the fuzzer_protocol.h interface
3. Add a libprot_newproto.so target in the Makefile
4. Register the new protocol in fuzzer.c with a proper enum and handler
The plugin system is designed to be minimal, self-contained, and portable.


License
------------------------

This project is licensed under the [MIT License](LICENSE).

> Use this software **only** in environments you **own** or have **explicit authorization** to test.
> Misuse of this tool is illegal and unethical.
