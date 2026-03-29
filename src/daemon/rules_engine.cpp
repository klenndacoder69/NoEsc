/*
 * NoEsc - Heuristic Detection Engine Implementation
 *
 * Detection Algorithms:
 *
 * 1. SUID/SGID Abuse (check_privilege_escalation):
 *    Triggers when auid≠0 but euid=0 from non-whitelisted binary.
 *    Path-based severity: /tmp=CRITICAL, /home=WARNING.
 *    Whitelist: System paths + config/suid_whitelist.conf
 *
 * 2. Sudo Misuse (check_sudo_misuse):
 *    Stateful scoring:
 *      - auth failures (+1)
 *      - dangerous sudo command launches (+5) for exec-like launch events
 *        (benign_exec key or execve syscall fallback)
 *    Progressive thresholds: 15=WARNING, 20=CRITICAL.
 *    60-second decay window, score resets after CRITICAL alert.
 *
 *    Notification behavior (SudoMisuse only):
 *      - first CRITICAL in an episode is shown immediately
 *      - subsequent CRITICALs in the same episode are suppressed and counted
 *      - a summary notification is emitted when the episode ends
 *        (quiet gap >= SUDO_NOTIFICATION_BURST_WINDOW_SECS)
 *      - pending suppressed alerts are also summarized at EOF/shutdown flush
 *
 * 3. Sensitive File Tampering (check_sensitive_access):
 *    Pattern matching on audit keys (identitychange, sudochange).
 *    Triggers when non-root process accesses protected files.
 *    Always CRITICAL severity.
 *
 * Alert Architecture:
 *   - Multi-tier: STDERR, file, syslog, desktop notification
 *   - Cooldown: 10s per-user per-vector
 *   - Severity filtering: CRITICAL-only desktop notifications
 */

#include "rules_engine.h"
#include <algorithm>
#include <cctype>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <syslog.h>
#include <unistd.h>

RulesEngine::RulesEngine() { load_config(); }

void RulesEngine::load_config() {
  std::ifstream file("/etc/noesc/suid_whitelist.conf");

  if (!file.is_open()) {
    file.open("config/suid_whitelist.conf");
  }

  if (!file.is_open()) {
    std::cerr
        << "[!] Warning: Could not open suid_whitelist.conf. Using defaults."
        << std::endl;
    return;
  }

  std::string line;
  while (std::getline(file, line)) {
    if (line.empty() || line[0] == '#')
      continue;
    custom_whitelist.push_back(line);
  }
  file.close();
}

AlertSeverity
RulesEngine::get_path_based_severity(const std::string &exe_path) {
  if (exe_path.find("/tmp/") == 0)
    return AlertSeverity::CRITICAL;
  if (exe_path.find("/dev/shm/") == 0)
    return AlertSeverity::CRITICAL;
  if (exe_path.find("/var/tmp/") == 0)
    return AlertSeverity::CRITICAL;

  if (exe_path.find("/home/") == 0)
    return AlertSeverity::WARNING;
  if (exe_path.find("/opt/") == 0)
    return AlertSeverity::WARNING;

  return AlertSeverity::CRITICAL;
}

void RulesEngine::evaluate(const LogEvent &event) {
  if (event.type == "SYSCALL") {
    check_privilege_escalation(event);
    check_sensitive_access(event);
  }
  check_sudo_misuse(event);
}

bool RulesEngine::is_sudo_exec_launch_event(const LogEvent &event) const {
  if (event.type != "SYSCALL" || event.success != "yes")
    return false;

  if (event.key == "benign_exec")
    return true;

  return event.syscall_id == 59 || event.syscall_id == 322;
}

bool RulesEngine::is_dangerous_sudo_exe(const std::string &exe) const {
  return exe == "/usr/bin/chmod" || exe == "/bin/chmod" ||
         exe == "/usr/bin/chown" || exe == "/bin/chown" ||
         exe == "/usr/bin/cp" || exe == "/bin/cp" ||
         exe == "/usr/bin/systemctl" || exe == "/bin/systemctl" ||
         exe == "/usr/bin/passwd" || exe == "/usr/sbin/useradd" ||
         exe == "/usr/bin/useradd" || exe == "/usr/sbin/usermod" ||
         exe == "/usr/bin/usermod" || exe == "/usr/sbin/visudo" ||
         exe == "/usr/bin/visudo" || exe == "/usr/bin/bash" ||
         exe == "/bin/bash" || exe == "/usr/bin/sh" || exe == "/bin/sh" ||
         exe == "/usr/bin/python3" || exe == "/usr/bin/python";
}

bool RulesEngine::is_maintenance_mode_active(long current_time) {
  if (current_time <= 0) {
    current_time = static_cast<long>(time(nullptr));
  }

  if (maintenance_mode_cache_check > 0 &&
      current_time - maintenance_mode_cache_check <
          MAINTENANCE_CACHE_REFRESH_SECS) {
    return maintenance_mode_until > current_time;
  }

  maintenance_mode_cache_check = current_time;
  maintenance_mode_until = 0;

  std::ifstream file(SUDO_MAINTENANCE_MODE_FILE);
  if (!file.is_open())
    return false;

  std::string line;
  if (!std::getline(file, line))
    return false;

  line.erase(std::remove_if(line.begin(), line.end(), [](unsigned char ch) {
               return std::isspace(ch);
             }),
             line.end());

  if (line.empty())
    return false;

  const std::string prefix = "until_epoch=";
  if (line.find(prefix) == 0) {
    line = line.substr(prefix.length());
  }

  try {
    maintenance_mode_until = std::stol(line);
  } catch (...) {
    maintenance_mode_until = 0;
  }

  return maintenance_mode_until > current_time;
}

void RulesEngine::maybe_send_sudo_notification(const std::string &title,
                                               const std::string &body,
                                               const LogEvent &event,
                                               AlertSeverity severity) {
  if (NOTIFY_CRITICAL_ONLY && severity != AlertSeverity::CRITICAL)
    return;

  long current_time = parse_timestamp(event.timestamp);
  if (current_time <= 0) {
    current_time = static_cast<long>(time(nullptr));
  }

  if (is_maintenance_mode_active(current_time)) {
    SudoNotifyBurstState &burst = sudo_notify_burst[event.auid];
    burst.last_critical_time = 0;
    burst.suppressed_count = 0;
    return;
  }

  if (severity != AlertSeverity::CRITICAL) {
    send_desktop_notification(title, body, severity);
    return;
  }

  SudoNotifyBurstState &burst = sudo_notify_burst[event.auid];

  bool new_episode = burst.last_critical_time == 0 ||
                     current_time - burst.last_critical_time >=
                         SUDO_NOTIFICATION_BURST_WINDOW_SECS;

  if (new_episode) {
    if (burst.suppressed_count > 0) {
      std::string summary =
          "High-frequency sudo activity: suppressed " +
          std::to_string(burst.suppressed_count) +
          " additional CRITICAL alerts in the last " +
          std::to_string(SUDO_NOTIFICATION_BURST_WINDOW_SECS) + "s.";
      send_desktop_notification(title + " (Burst Summary)", summary,
                                AlertSeverity::WARNING);
    }

    burst.suppressed_count = 0;
    burst.last_critical_time = current_time;
    send_desktop_notification(title, body, severity);
    return;
  }

  burst.suppressed_count++;
  burst.last_critical_time = current_time;
}

void RulesEngine::flush_pending_sudo_burst_summaries() {
  long current_time = static_cast<long>(time(nullptr));
  bool maintenance_active = is_maintenance_mode_active(current_time);

  for (auto &entry : sudo_notify_burst) {
    int auid = entry.first;
    SudoNotifyBurstState &burst = entry.second;

    if (burst.suppressed_count > 0 && !maintenance_active) {
      std::string summary =
          "High-frequency sudo activity: suppressed " +
          std::to_string(burst.suppressed_count) +
          " additional CRITICAL alerts in the last " +
          std::to_string(SUDO_NOTIFICATION_BURST_WINDOW_SECS) +
          "s before stream end (user " + std::to_string(auid) + ").";
      send_desktop_notification("[NoEsc] SudoMisuse (Final Burst Summary)",
                                summary, AlertSeverity::WARNING);
    }

    burst.suppressed_count = 0;
    burst.last_critical_time = 0;
  }
}

/*
 * Vector 1: SUID/SGID Binary Abuse Detection
 * Detects privilege escalation via non-standard SUID binaries
 */
void RulesEngine::check_privilege_escalation(const LogEvent &event) {
  if (event.success != "yes")
    return;
  if (!(event.euid == 0 && event.auid != 0 && event.auid != -1))
    return;

  bool is_standard_path = false;

  if (event.exe.find("/bin/") == 0)
    is_standard_path = true;
  else if (event.exe.find("/usr/bin/") == 0)
    is_standard_path = true;
  else if (event.exe.find("/sbin/") == 0)
    is_standard_path = true;
  else if (event.exe.find("/usr/sbin/") == 0)
    is_standard_path = true;
  else if (event.exe.find("/usr/lib/") == 0)
    is_standard_path = true;
  else if (event.exe.find("/usr/libexec/") == 0)
    is_standard_path = true;

  if (!is_standard_path) {
    for (const auto &path : custom_whitelist) {
      if (event.exe.find(path) == 0) {
        is_standard_path = true;
        break;
      }
    }
  }

  if (!is_standard_path) {
    long current_time = parse_timestamp(event.timestamp);
    auto it = priv_esc_cooldown.find(event.auid);
    if (it != priv_esc_cooldown.end() &&
        current_time - it->second < ALERT_COOLDOWN_SECS)
      return;
    priv_esc_cooldown[event.auid] = current_time;

    AlertSeverity severity = get_path_based_severity(event.exe);

    std::string msg =
        "SUID Abuse Detected! User " + std::to_string(event.auid) +
        " escalated to ROOT via NON-STANDARD binary: " + event.exe;
    alert("PrivilegeEscalation", msg, event, severity);
  }
}

/*
 * Vector 3: Sensitive File Tampering Detection
 * Triggers on audit keys: identitychange, sudochange
 */
void RulesEngine::check_sensitive_access(const LogEvent &event) {
  if (event.key != "identitychange" && event.key != "sudochange")
    return;

  if (event.syscall_id == 257 || event.syscall == "openat") {
    if (event.euid != 0) {
      std::string file_key = std::to_string(event.auid) + ":" + event.a0;
      long current_time = parse_timestamp(event.timestamp);
      auto it = sensitive_cooldown.find(file_key);
      if (it != sensitive_cooldown.end() &&
          current_time - it->second < ALERT_COOLDOWN_SECS)
        return;
      sensitive_cooldown[file_key] = current_time;

      std::string msg = "User " + std::to_string(event.auid) +
                        " (EUID=" + std::to_string(event.euid) +
                        ") attempted to modify: " + event.a0;
      alert("SensitiveTampering", msg, event, AlertSeverity::CRITICAL);
    }
  }
}

/*
 * Vector 2: Stateful Sudo Misuse Detection
 *
 * Current implementation summary:
 *   - Score sources:
 *       USER_AUTH failed => +1
 *       dangerous sudo exec launch => +5
 *   - Thresholds:
 *       WARNING at 15, CRITICAL at 20
 *   - Reset semantics:
 *       score decays to 0 after 60s inactivity
 *       score resets to 0 after CRITICAL alert emission
 *   - Desktop notification policy for SudoMisuse CRITICAL:
 *       first CRITICAL is shown immediately
 *       additional CRITICALs are aggregated and summarized at burst end/flush
 */
void RulesEngine::check_sudo_misuse(const LogEvent &event) {
  if (event.auid == -1 || event.auid == 0)
    return;

  SudoState &state = sudo_scores[event.auid];
  long current_time = parse_timestamp(event.timestamp);
  bool score_changed = false;

  if (current_time - state.last_event_time > SUDO_DECAY_WINDOW_SECS) {
    state.score = 0;
  }
  state.last_event_time = current_time;

  if (event.type == "USER_AUTH" && event.res == "failed") {
    state.score += SUDO_AUTH_FAIL_SCORE;
    score_changed = true;
  }

  if (event.euid == 0 && event.auid != 0 &&
      is_sudo_exec_launch_event(event)) {
    const std::string &exe = event.exe;
    if (is_dangerous_sudo_exe(exe)) {

      state.score += SUDO_DANGEROUS_CMD_SCORE;
      score_changed = true;
    }
  }

  if (score_changed) {
    if (state.score >= SUDO_WARNING_THRESHOLD &&
        state.score < SUDO_ALERT_THRESHOLD) {
      std::string msg =
          "Sudo Score Alert! User " + std::to_string(event.auid) +
          " approaching threshold (Score: " + std::to_string(state.score) +
          "/" + std::to_string(SUDO_ALERT_THRESHOLD) + ")";
      alert("SudoMisuse", msg, event, AlertSeverity::WARNING);
    }

    if (state.score >= SUDO_ALERT_THRESHOLD) {
      std::string msg =
          "Stateful Sudo Misuse Detected! Suspicion Score reached " +
          std::to_string(state.score) + "/" +
          std::to_string(SUDO_ALERT_THRESHOLD) + ".";
      alert("SudoMisuse", msg, event, AlertSeverity::CRITICAL);

      state.score = 0;
    }
  }
}

/*
 * Multi-Tier Alert Dispatcher
 * Channels: STDERR, file, syslog, desktop notification
 */
void RulesEngine::alert(const std::string &vector, const std::string &msg,
                        const LogEvent &event, AlertSeverity severity) {
  std::string context =
      " | Rule_Key=" + event.key + " | User=" + std::to_string(event.auid) +
      " (euid=" + std::to_string(event.euid) + ")" + " | Process=" + event.exe +
      " (pid=" + std::to_string(event.pid) +
      " ppid=" + std::to_string(event.ppid) + ")" + " | Command=" + event.comm +
      " | Args=[" + event.a0 + ", " + event.a1 + ", " + event.a2 + "]";

  std::string investigation;
  if (!event.serial.empty()) {
    investigation =
        " | INVESTIGATE: ausearch -a " + event.serial + " -i (exact event)";
  } else {
    investigation =
        " | INVESTIGATE: ausearch -p " + std::to_string(event.pid) + " -i";
  }

  std::string severity_str;
  switch (severity) {
  case AlertSeverity::INFO:
    severity_str = "INFO";
    break;
  case AlertSeverity::WARNING:
    severity_str = "WARNING";
    break;
  case AlertSeverity::CRITICAL:
    severity_str = "CRITICAL";
    break;
  }

  std::string full_msg = "[" + severity_str + "] [" + vector + "] " + msg +
                         context + investigation;

  std::cerr << "[!] NoEsc ALERT [" << vector << "]: " << msg << context
            << investigation << std::endl;

  const char *log_path = "/var/log/noesc_alerts.log";
  const char *fallback_path = "./noesc_alerts.log";

  std::ofstream log_file(log_path, std::ios_base::app);
  if (!log_file.is_open()) {
    log_file.open(fallback_path, std::ios_base::app);
  }

  if (log_file.is_open()) {
    log_file << "[" << event.timestamp << "] " << severity_str << " ALERT ["
             << vector << "]: " << msg << context << investigation << "\n";
    log_file.close();
  } else {
    std::cerr << "[!] WARNING: Failed to write alert to log file" << std::endl;
  }

  if (severity == AlertSeverity::CRITICAL || severity == AlertSeverity::WARNING){
    int syslog_priority;
    switch (severity) {
    case AlertSeverity::INFO:
      syslog_priority = LOG_INFO;
      break;
    case AlertSeverity::WARNING:
      syslog_priority = LOG_WARNING;
      break;
    case AlertSeverity::CRITICAL:
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

  if (vector == "SudoMisuse") {
    maybe_send_sudo_notification("[NoEsc] " + vector, msg, event, severity);
  } else {
    if (NOTIFY_CRITICAL_ONLY) {
      if (severity == AlertSeverity::CRITICAL) {
        send_desktop_notification("[NoEsc] " + vector, msg, severity);
      }
    } else {
      send_desktop_notification("[NoEsc] " + vector, msg, severity);
    }
  }
}

/*
 * Desktop Notification Dispatcher
 * Auto-detects user session, works as root or user
 */
void RulesEngine::send_desktop_notification(const std::string &title,
                                            const std::string &body,
                                            AlertSeverity severity) {
  std::string urgency = "normal";
  std::string icon = "dialog-warning";

  /* notify-send is a built-in Linux command that sends desktop notifications
   * using the D-Bus interface. however, its option -t or --expire-time does not
   * work in addition with certain other options of notify-send (such as the use
   * of -u or --urgency) please see
   * https://bugs.launchpad.net/ubuntu/+source/notify-osd/+bug/390508 the
   * workaround consists of using the D-Bus interface directly to send the
   * notification and then close it after a delay using a separate command. this
   * enables us to use notify-send with the desired options while still ensuring
   * the notification closes automatically
   */
  // code referenced from the user @Madacol (https://askubuntu.com/a/1525890)
  // gdbus call \
  //       --session \
  //       --dest org.freedesktop.Notifications \
  //       --object-path /org/freedesktop/Notifications \
  //       --method org.freedesktop.Notifications.Notify \
  //       "App_name" 0 "audio-headphones" "Title" "Message" '[]' '{}' 5000 \
  //   | sed -E 's/.uint32 ([0-9]+).*/\1/' \
  //   | xargs -I{notification_id} sh -c 'sleep 1 && gdbus call \
  //       --session \
  //       --dest org.freedesktop.Notifications \
  //       --object-path /org/freedesktop/Notifications \
  //       --method org.freedesktop.Notifications.CloseNotification
  //       {notification_id}'

  std::string notify_sleep_cmd =
      " | xargs -r -I{} sh -c \"sleep " + std::to_string(NOTIFICATION_DELAY) +
      " && gdbus call --session "
      "--dest org.freedesktop.Notifications "
      "--object-path /org/freedesktop/Notifications "
      "--method org.freedesktop.Notifications.CloseNotification {}\"";

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

  std::string safe_title = title;
  std::string safe_body = body;

  for (char &c : safe_title) {
    if (c == '"' || c == '\'' || c == '`' || c == '$' || c == '\\')
      c = '\'';
  }
  for (char &c : safe_body) {
    if (c == '"' || c == '\'' || c == '`' || c == '$' || c == '\\')
      c = '\'';
  }

  if (safe_body.length() > 200) {
    safe_body = safe_body.substr(0, 197) + "...";
  }

  if (getuid() == 0) {
    FILE *who_pipe =
        popen("who | grep '(:' | awk '{print $1}' | head -n1", "r");
    if (!who_pipe)
      return;

    char username[256] = {0};
    if (fgets(username, sizeof(username), who_pipe) == nullptr) {
      pclose(who_pipe);
      return;
    }
    pclose(who_pipe);

    size_t len = strlen(username);
    if (len > 0 && username[len - 1] == '\n') {
      username[len - 1] = '\0';
    }

    if (strlen(username) == 0)
      return;

    FILE *uid_pipe = popen(("id -u " + std::string(username)).c_str(), "r");
    if (!uid_pipe)
      return;

    char uid_str[32] = {0};
    if (fgets(uid_str, sizeof(uid_str), uid_pipe) == nullptr) {
      pclose(uid_pipe);
      return;
    }
    pclose(uid_pipe);
    size_t uid_len = strlen(uid_str);
    if (uid_len > 0 && uid_str[uid_len - 1] == '\n') {
      uid_str[uid_len - 1] = '\0';
    }

    // Used export since session will be a root ran in a program. since there are multiple commands that are being ran, using export we guarantee that 
    // the next processes would get the DBUS session address.
    std::string notify_cmd =
        "su " + std::string(username) +
      " -c 'export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" +
      std::string(uid_str) +
      "/bus; notify-send -p --app-name=NoEsc --urgency=" + urgency +
        " --icon=" + icon + " \"" + safe_title + "\"" + " \"" + safe_body +
        "\" 2>/dev/null" + notify_sleep_cmd + " >/dev/null 2>&1' &";

    system(notify_cmd.c_str());

  } else {
    std::string notify_cmd =
        "notify-send -p --app-name=NoEsc --urgency=" + urgency +
        " --icon=" + icon + " \"" + safe_title + "\"" + " \"" + safe_body +
        "\" 2>/dev/null" + notify_sleep_cmd + " >/dev/null 2>&1 &";

    system(notify_cmd.c_str());
  }

  usleep(150000);
}

long RulesEngine::parse_timestamp(const std::string &ts_str) {
  size_t dot_pos = ts_str.find('.');
  if (dot_pos == std::string::npos)
    return 0;
  try {
    return std::stol(ts_str.substr(0, dot_pos));
  } catch (...) {
    return 0;
  }
}
