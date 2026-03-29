/*
 * NoEsc - Heuristic Rule-Based Detection Engine
 *
 * Implements three privilege escalation detection vectors:
 *   1. SUID/SGID Binary Abuse (stateless, path-based severity)
 *   2. Sudo Misuse (stateful scoring with progressive alerting)
 *   3. Sensitive File Tampering (pattern matching on audit keys)
 *
 * Alert Severity Levels:
 *   CRITICAL - Immediate threat (desktop notification + all logs)
 *   WARNING  - Suspicious activity (logged, no desktop notification)
 *   INFO     - Informational (future use)
 *
 * Configuration Constants:
 *   SUDO_ALERT_THRESHOLD: Critical alert at 20 points
 *   SUDO_WARNING_THRESHOLD: Early warning at 15 points
 *   SUDO_DECAY_WINDOW_SECS: Score resets after 60s inactivity
 *   ALERT_COOLDOWN_SECS: Rate limit duplicate alerts (10s)
 *   NOTIFY_CRITICAL_ONLY: Filter desktop notifications
 */

#ifndef RULES_ENGINE_H
#define RULES_ENGINE_H

#include "Event.h"
#include <string>
#include <unordered_map>
#include <vector>

enum class AlertSeverity { CRITICAL, WARNING, INFO };

static constexpr int SUDO_ALERT_THRESHOLD = 20;
static constexpr int SUDO_WARNING_THRESHOLD = 15;
static constexpr long SUDO_DECAY_WINDOW_SECS = 60;
static constexpr int SUDO_AUTH_FAIL_SCORE = 1;
static constexpr int SUDO_DANGEROUS_CMD_SCORE = 5;
static constexpr bool NOTIFY_CRITICAL_ONLY = true;
static constexpr int NOTIFICATION_DELAY = 5;
static constexpr long SUDO_NOTIFICATION_BURST_WINDOW_SECS = 30;
static constexpr long MAINTENANCE_CACHE_REFRESH_SECS = 5;
static constexpr const char *SUDO_MAINTENANCE_MODE_FILE =
  "/etc/noesc/sudo_maintenance_mode.until";

struct SudoState {
  int score = 0;
  long last_event_time = 0;
};

struct SudoNotifyBurstState {
  long last_critical_time = 0;
  int suppressed_count = 0;
};

class RulesEngine {
public:
  RulesEngine();
  void evaluate(const LogEvent &event);
  void flush_pending_sudo_burst_summaries();

private:
  std::vector<std::string> custom_whitelist;
  std::unordered_map<int, SudoState> sudo_scores;
  std::unordered_map<int, SudoNotifyBurstState> sudo_notify_burst;
  std::unordered_map<int, long> priv_esc_cooldown;
  std::unordered_map<std::string, long> sensitive_cooldown;
  long maintenance_mode_cache_check = 0;
  long maintenance_mode_until = 0;

  static constexpr long ALERT_COOLDOWN_SECS = 10;

  void load_config();
  long parse_timestamp(const std::string &ts_str);

  void check_privilege_escalation(const LogEvent &event);
  void check_sudo_misuse(const LogEvent &event);
  void check_sensitive_access(const LogEvent &event);

  bool is_sudo_exec_launch_event(const LogEvent &event) const;
  bool is_dangerous_sudo_exe(const std::string &exe) const;
  bool is_maintenance_mode_active(long current_time);
  void maybe_send_sudo_notification(const std::string &title,
                                    const std::string &body,
                                    const LogEvent &event,
                                    AlertSeverity severity);

  AlertSeverity get_path_based_severity(const std::string &exe_path);
  void alert(const std::string &vector, const std::string &msg,
             const LogEvent &event, AlertSeverity severity);
  void send_desktop_notification(const std::string &title,
                                 const std::string &body,
                                 AlertSeverity severity);
};

#endif
