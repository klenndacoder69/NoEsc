#include "rules_engine.h"
#include <fstream>
#include <iostream>
#include <syslog.h>

RulesEngine::RulesEngine() { load_config(); }

void RulesEngine::load_config() {
  // Look for the config file in the standard system directory,
  std::ifstream file("/etc/noesc/suid_whitelist.conf");

  if (!file.is_open()) {
    file.open("config/suid_whitelist.conf");
  }

  if (!file.is_open()) {
    std::cerr << "[!] Warning: Could not open /etc/noesc/suid_whitelist.conf. "
                 "Using only hardcoded defaults."
              << std::endl;
    return;
  }

  std::string line;
  while (std::getline(file, line)) {
    // Skip empty lines and comments
    if (line.empty() || line[0] == '#')
      continue;

    // Add to whitelist
    custom_whitelist.push_back(line);
  }
  file.close();
}

void RulesEngine::evaluate(const LogEvent &event) {
  // Dispatch events to appropriate heuristics based on type
  if (event.type == "SYSCALL") {
    check_privilege_escalation(event);
    check_sensitive_access(event);
  }

  // Stateful checks might need multiple types (e.g., USER_AUTH and SYSCALL)
  check_sudo_misuse(event);
}

void RulesEngine::check_privilege_escalation(const LogEvent &event) {
  // Heuristic 1: Root Escalation (SUID/SGID Abuse)
  // Alert if:
  // 1. Execution succeeded
  // 2. auid != 0 (non-root login user)
  // 3. euid == 0 (process gained root)
  // 4. exe is NOT in a known-safe system path

  if (event.success != "yes") return;
  if (!(event.euid == 0 && event.auid != 0 && event.auid != -1)) return;

  bool is_standard_path = false;

  // Standard system binary and library paths (parser strips quotes, no need for quoted variants)
  if      (event.exe.find("/bin/") == 0)         is_standard_path = true;
  else if (event.exe.find("/usr/bin/") == 0)      is_standard_path = true;
  else if (event.exe.find("/sbin/") == 0)         is_standard_path = true;
  else if (event.exe.find("/usr/sbin/") == 0)     is_standard_path = true;
  else if (event.exe.find("/usr/lib/") == 0)      is_standard_path = true;
  else if (event.exe.find("/usr/libexec/") == 0)  is_standard_path = true;

  // Dynamic whitelist from config
  if (!is_standard_path) {
    for (const auto &path : custom_whitelist) {
      if (event.exe.find(path) == 0) {
        is_standard_path = true;
        break;
      }
    }
  }

  if (!is_standard_path) {
    // Cooldown: suppress duplicate alerts for the same user within 10s
    long current_time = parse_timestamp(event.timestamp);
    auto it = priv_esc_cooldown.find(event.auid);
    if (it != priv_esc_cooldown.end() && current_time - it->second < ALERT_COOLDOWN_SECS)
      return;
    priv_esc_cooldown[event.auid] = current_time;

    std::string msg = "SUID Abuse Detected! User " + std::to_string(event.auid) +
                      " escalated to ROOT via NON-STANDARD binary: " + event.exe;
    alert("PrivilegeEscalation", msg, event, AlertSeverity::CRITICAL);
  }
}

void RulesEngine::check_sensitive_access(const LogEvent &event) {
  // Heuristic 3: Sensitive File Tampering (Pattern Matching)
  // Keys: "identitychange", "sudochange" (from harvest_logs.sh)
  // We removed "perm" to avoid noise from generic chmod calls.

  bool is_sensitive_key =
      (event.key.find("identitychange") != std::string::npos) ||
      (event.key.find("sudochange") != std::string::npos);

  if (is_sensitive_key) {
    if (event.euid != 0) {
      // Cooldown: suppress duplicate alerts for the same user within 10s
      long current_time = parse_timestamp(event.timestamp);
      auto it = sensitive_cooldown.find(event.auid);
      if (it != sensitive_cooldown.end() && current_time - it->second < ALERT_COOLDOWN_SECS)
        return;
      sensitive_cooldown[event.auid] = current_time;

      std::string msg =
          "Unauthorized Modification Attempt! Non-Root User (EUID=" +
          std::to_string(event.euid) + ") modified a critical file.";
      alert("SensitiveTampering", msg, event, AlertSeverity::CRITICAL);
    }
  }
}

long RulesEngine::parse_timestamp(const std::string &ts_str) {
  if (ts_str.empty())
    return 0;
  try {
    size_t dot = ts_str.find('.');
    if (dot != std::string::npos) {
      return std::stol(ts_str.substr(0, dot));
    }
    return std::stol(ts_str);
  } catch (...) {
    return 0;
  }
}

void RulesEngine::check_sudo_misuse(const LogEvent &event) {
  // 1. Ignore root/system daemons (only track real users)
  if (event.auid <= 0)
    return;

  long current_time = parse_timestamp(event.timestamp);
  if (current_time == 0)
    return;

  // 2. Get or create state for this user
  SudoState &state = sudo_scores[event.auid];

  // 3. Time Decay: reset score on ANY event if more than SUDO_DECAY_WINDOW_SECS since last activity
  if (state.last_event_time > 0 && (current_time - state.last_event_time) > SUDO_DECAY_WINDOW_SECS) {
    state.score = 0;
  }
  // Update timestamp on every event so decay window stays accurate
  state.last_event_time = current_time;

  bool score_changed = false;

  // 4. Rule A: Authentication Failure (+SUDO_AUTH_FAIL_SCORE point)
  if (event.type == "USER_AUTH" || event.type == "USER_ERR") {
    if (event.res.find("failed") != std::string::npos) {
      state.score += SUDO_AUTH_FAIL_SCORE;
      score_changed = true;
    }
  }

  // 5. Rule B: Dangerous Command Executed as Root via Sudo (+SUDO_DANGEROUS_CMD_SCORE points)
  if (event.type == "SYSCALL" && event.euid == 0 && event.auid != 0 &&
      event.success == "yes") {
    const std::string &exe = event.exe;
    if (exe == "/usr/bin/chmod"    || exe == "/bin/chmod"    ||
        exe == "/usr/bin/chown"    || exe == "/bin/chown"    ||
        exe == "/usr/bin/cp"       || exe == "/bin/cp"       ||
        exe == "/usr/bin/systemctl"|| exe == "/bin/systemctl"||
        // Account manipulation
        exe == "/usr/bin/passwd"   ||
        exe == "/usr/sbin/useradd" || exe == "/usr/bin/useradd" ||
        exe == "/usr/sbin/usermod" || exe == "/usr/bin/usermod" ||
        // Sudoers editing
        exe == "/usr/sbin/visudo"  || exe == "/usr/bin/visudo" ||
        // Shell / interpreter spawning (GTFOBins)
        exe == "/usr/bin/bash"     || exe == "/bin/bash"     ||
        exe == "/usr/bin/sh"       || exe == "/bin/sh"       ||
        exe == "/usr/bin/python3"  || exe == "/usr/bin/python") {

      state.score += SUDO_DANGEROUS_CMD_SCORE;
      score_changed = true;
    }
  }

  // 6. Debug: log score changes when DEBUG_SCORING is defined
#ifdef DEBUG_SCORING
  if (score_changed) {
    std::cerr << "[~] SudoMisuse score for AUID=" << event.auid
              << " -> " << state.score << "/" << SUDO_ALERT_THRESHOLD
              << " (exe=" << event.exe << ")" << std::endl;
  }
#endif

  // 7. Threshold Check (Alert if >= SUDO_ALERT_THRESHOLD)
  if (score_changed && state.score >= SUDO_ALERT_THRESHOLD) {
    std::string msg =
        "Stateful Sudo Misuse Detected! Suspicion Score reached " +
        std::to_string(state.score) + "/" + std::to_string(SUDO_ALERT_THRESHOLD) + ".";
    alert("SudoMisuse", msg, event, AlertSeverity::CRITICAL);

    // Reset score after alert to avoid log flooding
    state.score = 0;
  }
}

void RulesEngine::alert(const std::string &vector, const std::string &msg,
                        const LogEvent &event, AlertSeverity severity) {
  // Construct a verbose, context-rich alert message
  std::string context =
      " | Rule_Key=" + event.key + " | User=" + std::to_string(event.auid) +
      " (euid=" + std::to_string(event.euid) + ")" + " | Process=" + event.exe +
      " (pid=" + std::to_string(event.pid) +
      " ppid=" + std::to_string(event.ppid) + ")" + " | Command=" + event.comm +
      " | Args=[" + event.a0 + ", " + event.a1 + ", " + event.a2 + "]";

  // Add actionable investigation guidance for administrators
  // Provide both event ID (exact event) and PID (process context)
  std::string investigation;
  if (!event.serial.empty()) {
    investigation = " | INVESTIGATE: ausearch -a " + event.serial + " -i (exact event)";
  } else {
    investigation = " | INVESTIGATE: ausearch -p " + std::to_string(event.pid) + " -i";
  }

  std::string severity_str;
  switch (severity) {
    case AlertSeverity::INFO: severity_str = "INFO"; break;
    case AlertSeverity::WARNING: severity_str = "WARNING"; break;
    case AlertSeverity::CRITICAL: severity_str = "CRITICAL"; break;
  }

  std::string full_msg = "[" + severity_str + "] [" + vector + "] " + msg + context + investigation;
  // 1. Print to STDERR (Visible when running manually in the terminal for
  // testing)
  std::cerr << "[!] NoEsc ALERT [" << vector << "]: " << msg << context
            << investigation << std::endl;

  // 2. Append to Dedicated System Log File (For Daemon Mode)
  // Note: Daemon runs as root, so it has permission to write here.
  // For testing, fall back to local file if /var/log is not writable
  const char* log_path = "/var/log/noesc_alerts.log";
  const char* fallback_path = "./noesc_alerts.log";
  
  std::ofstream log_file(log_path, std::ios_base::app);
  if (!log_file.is_open()) {
    // Try fallback location for non-root testing
    log_file.open(fallback_path, std::ios_base::app);
  }
  
  if (log_file.is_open()) {
    log_file << "[" << event.timestamp << "] "
             << "ALERT [" << vector << "]: " << msg << context << investigation << "\n";
    log_file.close();
  } else {
    // If we can't write to either location, ensure the error is visible
    std::cerr << "[!] WARNING: Failed to write alert to " << log_path 
              << " and " << fallback_path << std::endl;
  }

  if (severity >= AlertSeverity::WARNING) {
    int syslog_priority;
    switch (severity) {
      case AlertSeverity::INFO:
        syslog_priority = LOG_INFO;
        break; 
      case AlertSeverity::WARNING:
        syslog_priority = LOG_WARNING;
        break;
      case AlertSeverity:: CRITICAL:
        syslog_priority = LOG_CRIT;
        break;
    }
    static bool syslog_opened = false;
    if (!syslog_opened) {
      openlog("noesc", LOG_PID | LOG_CONS, LOG_AUTH);
      syslog_opened = true;
    }

    syslog(syslog_priority, "%s", full_msg.c_str());
    }
}
