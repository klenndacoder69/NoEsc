#include "rules_engine.h"
#include <fstream>
#include <iostream>

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
  // REVISED Logic (Strict Whitelist - Stronger than Paper):
  // Alert if:
  // 1. auid != 0 (Non-root user)
  // 2. euid == 0 (Becomes Root)
  // 3. exe is NOT in a standard system binary directory (/bin, /usr/bin, /sbin,
  // /usr/sbin)
  // BASTA BLACKLIST

  if (event.euid == 0 && event.auid != 0 && event.auid != -1) {
    bool is_standard_path = false;

    // Check against Standard System Paths
    // Handles unquoted paths
    if (event.exe.find("/bin/") == 0)
      is_standard_path = true;
    else if (event.exe.find("/usr/bin/") == 0)
      is_standard_path = true;
    else if (event.exe.find("/sbin/") == 0)
      is_standard_path = true;
    else if (event.exe.find("/usr/sbin/") == 0)
      is_standard_path = true;

    // Handles quoted paths (parser might leave quotes)
    else if (event.exe.find("\"/bin/") == 0)
      is_standard_path = true;
    else if (event.exe.find("\"/usr/bin/") == 0)
      is_standard_path = true;
    else if (event.exe.find("\"/sbin/") == 0)
      is_standard_path = true;
    else if (event.exe.find("\"/usr/sbin/") == 0)
      is_standard_path = true;

    // System Library Paths (for legitimate daemons like systemd-executor,
    // gdm-session-worker)
    else if (event.exe.find("/usr/lib/") == 0)
      is_standard_path = true;
    else if (event.exe.find("\"/usr/lib/") == 0)
      is_standard_path = true;
    else if (event.exe.find("/usr/libexec/") == 0)
      is_standard_path = true;
    else if (event.exe.find("\"/usr/libexec/") == 0)
      is_standard_path = true;

    // Check against dynamic configuration file
    if (!is_standard_path) {
      for (const auto &path : custom_whitelist) {
        if (event.exe.find(path) == 0 || event.exe.find("\"" + path) == 0) {
          is_standard_path = true;
          break;
        }
      }
    }

    if (!is_standard_path) {
      std::string msg =
          "SUID Abuse Detected! User " + std::to_string(event.auid) +
          " escalated to ROOT via NON-STANDARD binary: " + event.exe;
      alert("PrivilegeEscalation", msg, event);
    }
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
    // Logic: Alert ONLY if the process performing the change is NOT running as
    // Root (EUID != 0) Root is allowed to change these files. Normal users are
    // not.
    if (event.euid != 0) {
      std::string msg =
          "Unauthorized Modification Attempt! Non-Root User (EUID=" +
          std::to_string(event.euid) + ") modified a critical file.";
      alert("SensitiveTampering", msg, event);
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
    return; // Invalid time

  // 2. Get or create state for this user
  SudoState &state = sudo_scores[event.auid];

  // 3. Time Decay (Sliding Window of 60 seconds)
  if (state.last_event_time > 0 &&
      (current_time - state.last_event_time) > 60) {
    state.score =
        0; // Reset score if it's been more than 60s since last suspicious act
  }

  bool score_changed = false;

  // 4. Rule A: Authentication Failure (+1 point)
  if (event.type == "USER_AUTH" || event.type == "USER_ERR") {
    if (event.res.find("failed") != std::string::npos) {
      state.score += 1;
      state.last_event_time = current_time;
      score_changed = true;
    }
  }

  // 5. Rule B: Dangerous Sudo Command (+5 points)
  // The paper originally proposed +10, but tuned to +5 for lab environments
  if (event.type == "SYSCALL" && event.euid == 0 && event.auid != 0 &&
      event.success == "yes") {
    std::string exe = event.exe;
    // Strip quotes if parser left them
    if (!exe.empty() && exe[0] == '"')
      exe = exe.substr(1, exe.length() - 2);

    if (exe == "/usr/bin/chmod" || exe == "/bin/chmod" ||
        exe == "/usr/bin/chown" || exe == "/bin/chown" ||
        exe == "/usr/bin/cp" || exe == "/bin/cp" ||
        exe == "/usr/bin/systemctl" || exe == "/bin/systemctl") {

      state.score += 5;
      state.last_event_time = current_time;
      score_changed = true;
    }
  }

  // 6. Threshold Check (Alert if >= 20)
  if (score_changed && state.score >= 20) {
    std::string msg =
        "Stateful Sudo Misuse Detected! Suspicion Score reached " +
        std::to_string(state.score) + "/20.";
    alert("SudoMisuse", msg, event);

    // Reset score after alert to avoid spamming the logs
    state.score = 0;
  }
}

void RulesEngine::alert(const std::string &vector, const std::string &msg,
                        const LogEvent &event) {
  // Construct a verbose, context-rich alert message
  std::string context =
      " | Rule_Key=" + event.key + " | User=" + std::to_string(event.auid) +
      " (euid=" + std::to_string(event.euid) + ")" + " | Process=" + event.exe +
      " (pid=" + std::to_string(event.pid) +
      " ppid=" + std::to_string(event.ppid) + ")" + " | Command=" + event.comm +
      " | Args=[" + event.a0 + ", " + event.a1 + ", " + event.a2 + "]";

  // 1. Print to STDERR (Visible when running manually in the terminal for
  // testing)
  std::cerr << "[!] NoEsc ALERT [" << vector << "]: " << msg << context
            << std::endl;

  // 2. Append to Dedicated System Log File (For Daemon Mode)
  // Note: Daemon runs as root, so it has permission to write here.
  std::ofstream log_file("/var/log/noesc_alerts.log", std::ios_base::app);
  if (log_file.is_open()) {
    log_file << "[" << event.timestamp << "] "
             << "ALERT [" << vector << "]: " << msg << context << "\n";
    log_file.close();
  }
}
