# Linux Privilege Escalation Detector

## Project Overview

**NoEsc** is a specialized security tool designed to detect and identify privilege escalation attempts and vulnerabilities in Linux systems. This project serves as an Undergraduate Thesis for the Computer Science program at the University of the Philippines Los Baños (UPLB), Institute of Computer Science.

## Author

**Klenn Jakek V. Borja and Joseph Anthony C. Hermocilla**  
University of the Philippines Los Baños (UPLB)  
Institute of Computer Science  
Email: [kvborja@up.edu.ph](mailto:kvborja@up.edu.ph)

## Legal Disclaimer

This tool is provided for **educational and authorized security testing purposes only** as part of an undergraduate thesis at UPLB. 

**Important:** You may only use NoEsc on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal and unethical. The authors assume no liability for misuse, damage, or legal consequences resulting from the unauthorized use of this tool.

## Build Instructions

### Prerequisites
- `auditd` and `audispd-plugins`
- C++17 compliant compiler (g++ or clang)
- CMake (optional)

### Compiling the Daemon

**Option 1: Using CMake**
```bash
mkdir build && cd build
cmake ..
make
```

**Option 2: Using G++ Directly**
```bash
g++ -std=c++17 src/daemon/main.cpp src/daemon/parser.cpp src/daemon/rules_engine.cpp -o noesc_daemon -I src/daemon
```

## Configuration

1. Copy the plugin configuration:
   ```bash
   sudo cp config/noesc.conf /etc/audit/plugins.d/
   ```
2. Ensure the daemon executable is in the path specified in `noesc.conf` (default: `/usr/local/bin/noesc_daemon`).
3. Reload auditd:
   ```bash
   sudo service auditd reload
   ```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
