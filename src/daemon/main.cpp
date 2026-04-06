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
          ml_bridge.dump_event_json_stdout(event);
        } else {
          ml_bridge.send_event(event);
        }
        engine.evaluate(event);
      }
    } catch (const std::exception &e) {
      std::cerr << "[!] Error processing line: " << e.what() << std::endl;
    }
  }

  engine.flush_pending_sudo_burst_summaries();
  if (!dump_json_mode) {
    ml_bridge.shutdown();
  }

  return 0;
}
