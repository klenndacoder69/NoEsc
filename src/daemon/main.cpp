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
#include <algorithm>
#include <cctype>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>

volatile sig_atomic_t running = 1;

void signal_handler(int) { 
  running = 0; 
}

enum class EngineMode { Hybrid, MlOnly, RulesOnly };

static std::string to_lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

static bool parse_engine_mode(const std::string &raw_mode, EngineMode &mode_out) {
  const std::string mode = to_lower_copy(raw_mode);
  if (mode == "hybrid") {
    mode_out = EngineMode::Hybrid;
    return true;
  }
  if (mode == "ml-only" || mode == "ml_only") {
    mode_out = EngineMode::MlOnly;
    return true;
  }
  if (mode == "rules-only" || mode == "rules_only") {
    mode_out = EngineMode::RulesOnly;
    return true;
  }
  return false;
}

static void print_usage(const char *program_name) {
  std::cerr << "Usage: " << program_name
            << " [--dump-json] [--ml-only | --rules-only]" << std::endl;
  std::cerr << "  Env override: NOESC_ENGINE_MODE={hybrid|ml-only|rules-only}"
            << std::endl;
}

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

  if (exe.find("noesc_daemon") != std::string::npos) {
    return true;
  }

  return false;
}

// Keep dump-json output aligned with ML feature-parity contract fields.
static bool should_export_dump_json_event(const LogEvent &event) {
  const bool is_syscall_event = event.type == "SYSCALL";
  const bool is_user_auth_event = event.type == "USER_AUTH";

  if (!is_syscall_event && !is_user_auth_event) {
    return false;
  }

  if (event.pid < 0) {
    return false;
  }

  // SYSCALL events require stable user identifiers for feature generation.
  if (is_syscall_event && (event.auid < 0 || event.euid < 0)) {
    return false;
  }

  // USER_AUTH may legitimately carry unset auid (e.g., login manager paths).
  if (is_user_auth_event && event.euid < 0) {
    return false;
  }

  if (is_syscall_event && event.syscall.empty() && event.syscall_id < 0) {
    return false;
  }

  if (is_syscall_event && is_dump_json_contaminant_exe(event.exe)) {
    return false;
  }

  return true;
}

int main(int argc, char **argv) {
  bool dump_json_mode = false;
  EngineMode engine_mode = EngineMode::Hybrid;
  bool mode_set_by_cli = false;

  const char *env_mode_raw = std::getenv("NOESC_ENGINE_MODE");
  if (env_mode_raw != nullptr && env_mode_raw[0] != '\0') {
    if (!parse_engine_mode(env_mode_raw, engine_mode)) {
      std::cerr << "[!] Invalid NOESC_ENGINE_MODE: " << env_mode_raw << std::endl;
      print_usage(argv[0]);
      return 1;
    }
  }

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--dump-json") {
      dump_json_mode = true;
    } else if (arg == "--ml-only") {
      if (mode_set_by_cli && engine_mode != EngineMode::MlOnly) {
        std::cerr << "[!] Conflicting engine mode flags" << std::endl;
        print_usage(argv[0]);
        return 1;
      }
      engine_mode = EngineMode::MlOnly;
      mode_set_by_cli = true;
    } else if (arg == "--rules-only") {
      if (mode_set_by_cli && engine_mode != EngineMode::RulesOnly) {
        std::cerr << "[!] Conflicting engine mode flags" << std::endl;
        print_usage(argv[0]);
        return 1;
      }
      engine_mode = EngineMode::RulesOnly;
      mode_set_by_cli = true;
    } else if (arg == "-h" || arg == "--help") {
      print_usage(argv[0]);
      return 0;
    } else {
      std::cerr << "[!] Unknown argument: " << arg << std::endl;
      print_usage(argv[0]);
      return 1;
    }
  }

  if (dump_json_mode && engine_mode != EngineMode::Hybrid) {
    std::cerr << "[!] --dump-json cannot be combined with engine mode flags"
              << std::endl;
    print_usage(argv[0]);
    return 1;
  }

  const bool enable_ml_bridge = !dump_json_mode && engine_mode != EngineMode::RulesOnly;
  const bool enable_rules = !dump_json_mode && engine_mode != EngineMode::MlOnly;

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  RulesEngine engine;
  UdsBridge ml_bridge;
  LogEvent event;
  std::string line;

  if (enable_ml_bridge) {
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
          if (enable_ml_bridge) {
            ml_bridge.send_event(event);
          }
          if (enable_rules) {
            engine.evaluate(event);
          }
        }
      }
    } catch (const std::exception &e) {
      std::cerr << "[!] Error processing line: " << e.what() << std::endl;
    }
  }

  if (!dump_json_mode) {
    if (enable_rules) {
      engine.flush_pending_sudo_burst_summaries();
    }
    if (enable_ml_bridge) {
      ml_bridge.shutdown();
    }
  }

  return 0;
}
