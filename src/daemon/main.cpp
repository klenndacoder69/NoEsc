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
#include <csignal>
#include <iostream>
#include <string>
#include <unistd.h>

volatile sig_atomic_t running = 1;

void signal_handler(int) { 
  running = 0; 
}

int main() {
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  RulesEngine engine;
  LogEvent event;
  std::string line;

  std::ios_base::sync_with_stdio(false);
  std::cin.tie(NULL);

  while (running && std::getline(std::cin, line)) {
    try {
      if (AuditParser::parse_line(line, event)) {
        engine.evaluate(event);
      }
    } catch (const std::exception &e) {
      std::cerr << "[!] Error processing line: " << e.what() << std::endl;
    }
  }

  return 0;
}
