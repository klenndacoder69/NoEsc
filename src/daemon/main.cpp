/*
 * NoEsc - Host-Based Intrusion Detection System (HIDS)
 * Main Daemon Entry Point
 *
 * This daemon operates as an audispd plugin, receiving real-time audit events
 * via STDIN. It implements a hybrid detection approach:
 *   - Heuristic rule-based engine (SUID abuse, sudo misuse, file tampering)
 *   - Machine learning-based anomaly detection (SVM classifier)
 *
 * Data Flow:
 *   Kernel → auditd → audispd → NoEsc (this daemon) → Alert channels
 *
 * Alert Channels:
 *   1. STDERR (console output)
 *   2. /var/log/noesc_alerts.log (persistent file)
 *   3. Syslog (journald/rsyslog integration)
 *   4. Desktop notifications (notify-send)
 *
 */

#include "parser.h"
#include "rules_engine.h"
#include "uds_bridge.h"
#include <csignal>
#include <iostream>
#include <string>
#include <unistd.h>

volatile sig_atomic_t running = 1;

void signal_handler(int) { 
  running = 0; 
}

// Exclude known self-generated notification helper processes from offline
// training export, because they are side effects of alerting, not attack steps.
static bool is_dump_json_contaminant_exe(const std::string &exe) {
  if (exe.empty()) {
    return false;
  }

  if (exe == "/usr/bin/notify-send" || exe == "/usr/bin/xargs" ||
      exe == "/usr/bin/gdbus" || exe == "/usr/bin/plasmashell" ||
      exe == "/usr/bin/git" || exe == "/usr/bin/mktemp" ||
      exe == "/usr/bin/seq") {
    return true;
  }

  // Handle both absolute and installed paths that end with the daemon binary.
  if (exe.find("noesc_daemon") != std::string::npos) {
    return true;
  }

  return false;
}

// Keep dump-json output aligned with ML feature-parity contract fields.
static bool should_export_dump_json_event(const LogEvent &event) {
  if (event.type != "SYSCALL") {
    return false;
  }

  if (event.pid < 0 || event.auid < 0 || event.euid < 0) {
    return false;
  }

  if (event.syscall.empty() && event.syscall_id < 0) {
    return false;
  }

  if (is_dump_json_contaminant_exe(event.exe)) {
    return false;
  }

  return true;
}

int main(int argc, char **argv) {
  bool dump_json_mode = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--dump-json") {
      dump_json_mode = true;
    } else if (arg == "-h" || arg == "--help") {
      std::cerr << "Usage: " << argv[0] << " [--dump-json]" << std::endl;
      return 0;
    } else {
      std::cerr << "[!] Unknown argument: " << arg << std::endl;
      std::cerr << "Usage: " << argv[0] << " [--dump-json]" << std::endl;
      return 1;
    }
  }

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  RulesEngine engine;
  UdsBridge ml_bridge;
  LogEvent event;
  std::string line;

  if (!dump_json_mode) {
    ml_bridge.initialize();
  }

  std::ios_base::sync_with_stdio(false);
  std::cin.tie(NULL);

  while (running && std::getline(std::cin, line)) {
    try {
      if (AuditParser::parse_line(line, event)) {
        if (dump_json_mode) {
          if (!should_export_dump_json_event(event)) {
            continue;
          }
          ml_bridge.dump_event_json_stdout(event);
        } else {
          ml_bridge.send_event(event);
          engine.evaluate(event);
        }
      }
    } catch (const std::exception &e) {
      std::cerr << "[!] Error processing line: " << e.what() << std::endl;
    }
  }

  if (!dump_json_mode) {
    engine.flush_pending_sudo_burst_summaries();
    ml_bridge.shutdown();
  }

  return 0;
}
