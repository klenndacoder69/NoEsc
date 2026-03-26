#include "rules_engine.h"
#include <fstream>
#include <iostream>
#include <syslog.h>
#include <cstring>  // For strlen, strcpy
#include <cstdlib>  // For system, popen
#include <unistd.h> // For getuid()

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

AlertSeverity RulesEngine::get_path_based_severity(const std::string& exe_path) {
  // Risk assessment based on executable location
  // High-risk paths (commonly used by attackers) = CRITICAL
  // Medium-risk paths (could be legitimate student work) = WARNING
  
  // High-risk: temporary directories, shared memory, unusual locations
  if (exe_path.find("/tmp/") == 0)       return AlertSeverity::CRITICAL;
  if (exe_path.find("/dev/shm/") == 0)   return AlertSeverity::CRITICAL;
  if (exe_path.find("/var/tmp/") == 0)   return AlertSeverity::CRITICAL;
  
  // Medium-risk: user directories, optional software (could be coursework)
  if (exe_path.find("/home/") == 0)      return AlertSeverity::WARNING;
  if (exe_path.find("/opt/") == 0)       return AlertSeverity::WARNING;
  
  // Unknown paths = treat as critical (better safe than sorry)
  return AlertSeverity::CRITICAL;
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

    // Determine severity based on executable path (risk assessment)
    AlertSeverity severity = get_path_based_severity(event.exe);
    
    std::string msg = "SUID Abuse Detected! User " + std::to_string(event.auid) +
                      " escalated to ROOT via NON-STANDARD binary: " + event.exe;
    alert("PrivilegeEscalation", msg, event, severity);
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

  // 7. Progressive Threshold Checks (Early Warning + Critical Alert)
  if (score_changed) {
    // WARNING: Approaching threshold (15-19 points)
    if (state.score >= SUDO_WARNING_THRESHOLD && state.score < SUDO_ALERT_THRESHOLD) {
      std::string msg =
          "Sudo Score Alert! User " + std::to_string(event.auid) + 
          " approaching threshold (Score: " + std::to_string(state.score) + 
          "/" + std::to_string(SUDO_ALERT_THRESHOLD) + ")";
      alert("SudoMisuse", msg, event, AlertSeverity::WARNING);
    }
    
    // CRITICAL: Threshold reached (20+ points)
    if (state.score >= SUDO_ALERT_THRESHOLD) {
      std::string msg =
          "Stateful Sudo Misuse Detected! Suspicion Score reached " +
          std::to_string(state.score) + "/" + std::to_string(SUDO_ALERT_THRESHOLD) + ".";
      alert("SudoMisuse", msg, event, AlertSeverity::CRITICAL);

      // Reset score after alert to avoid log flooding
      state.score = 0;
    }
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
             << severity_str << " ALERT [" << vector << "]: " << msg << context << investigation << "\n";
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
  
  // 4. Send Desktop Notification (Visual Alert for Testing/Development)
  // Filter: Only send desktop notifications for CRITICAL alerts (reduce notification fatigue)
  if (NOTIFY_CRITICAL_ONLY) {
    if (severity == AlertSeverity::CRITICAL) {
      send_desktop_notification("[NoEsc] " + vector, msg, severity);
    }
  } else {
    // If filtering disabled, send all notifications
    send_desktop_notification("[NoEsc] " + vector, msg, severity);
  }
}

void RulesEngine::send_desktop_notification(const std::string& title, 
                                            const std::string& body, 
                                            AlertSeverity severity) {
  // Determine notification urgency and icon based on severity
  std::string urgency = "normal";
  std::string icon = "dialog-warning";
  
  switch (severity) {
    case AlertSeverity::CRITICAL:
      urgency = "critical";
      icon = "dialog-error";
      break;
    case AlertSeverity::WARNING:
      urgency = "normal";
      icon = "dialog-warning";
      break;
    case AlertSeverity::INFO:
      urgency = "low";
      icon = "dialog-information";
      break;
  }
  
  // Sanitize input to prevent command injection
  std::string safe_title = title;
  std::string safe_body = body;
  
  for (char& c : safe_title) {
    if (c == '"' || c == '`' || c == '$' || c == '\\') c = '\'';
  }
  for (char& c : safe_body) {
    if (c == '"' || c == '`' || c == '$' || c == '\\') c = '\'';
  }
  
  // Truncate body if too long (notify-send has limits)
  if (safe_body.length() > 200) {
    safe_body = safe_body.substr(0, 197) + "...";
  }
  
  // Check if running as root (getuid returns effective user ID)
  if (getuid() == 0) {
    // Running as root (daemon mode) - need to find user's session
    
    // Find the active graphical user
    FILE* who_pipe = popen("who | grep '(:' | awk '{print $1}' | head -n1", "r");
    if (!who_pipe) return;
    
    char username[256] = {0};
    if (fgets(username, sizeof(username), who_pipe) == nullptr) {
      pclose(who_pipe);
      return;
    }
    pclose(who_pipe);
    
    // Remove newline
    size_t len = strlen(username);
    if (len > 0 && username[len-1] == '\n') {
      username[len-1] = '\0';
    }
    
    if (strlen(username) == 0) return;
    
    // Get user's UID
    FILE* uid_pipe = popen(("id -u " + std::string(username)).c_str(), "r");
    if (!uid_pipe) return;
    
    char uid_str[32] = {0};
    if (fgets(uid_str, sizeof(uid_str), uid_pipe) == nullptr) {
      pclose(uid_pipe);
      return;
    }
    pclose(uid_pipe);
    
    // Build command to run as user with their DBUS session
    std::string notify_cmd = 
      "su " + std::string(username) + 
      " -c 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + std::string(uid_str) +
      "bus notify-send --urgency=" + urgency +
      " --icon=" + icon +
      " \"" + safe_title + "\"" +
      " \"" + safe_body + "\"' 2>/dev/null &";
    
    system(notify_cmd.c_str());
    
  } else {
    // Running as regular user (test mode) - direct notify-send
    std::string notify_cmd = 
      "notify-send --urgency=" + urgency +
      " --icon=" + icon +
      " \"" + safe_title + "\"" +
      " \"" + safe_body + "\" 2>/dev/null &";
    
    system(notify_cmd.c_str());
  }
  
  // Small delay to prevent notification overlap when multiple alerts trigger
  // Most notification daemons need ~100ms to register and stack notifications
  // This ensures each notification is visible and not replaced
  usleep(150000); // 150ms delay
}
