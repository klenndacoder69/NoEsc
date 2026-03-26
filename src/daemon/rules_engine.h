#ifndef RULES_ENGINE_H
#define RULES_ENGINE_H

#include "Event.h"
#include <string>
#include <vector>
#include <unordered_map>

enum class AlertSeverity{
    CRITICAL,
    WARNING,
    INFO
};

// Uncomment to enable per-event scoring debug output
// #define DEBUG_SCORING

// Configuration Constants
static constexpr int SUDO_ALERT_THRESHOLD = 20;        // Score threshold for sudo misuse alert
static constexpr long SUDO_DECAY_WINDOW_SECS = 60;     // Time window for score decay (seconds)
static constexpr int SUDO_AUTH_FAIL_SCORE = 1;         // Score increment for auth failure
static constexpr int SUDO_DANGEROUS_CMD_SCORE = 5;     // Score increment for dangerous command execution

// Struct for Vector 2: Stateful Scoring
struct SudoState {
    int score = 0;
    long last_event_time = 0; // Unix epoch timestamp
};

class RulesEngine {
public:
    RulesEngine(); // Constructor to load config

    /**
     * Evaluates a single parsed log event against heuristic rules.
     */
    void evaluate(const LogEvent& event);

private:
    std::vector<std::string> custom_whitelist;
    void load_config(); // Helper to read whitelist file

    // State map for Sudo Misuse (AUID -> State)
    std::unordered_map<int, SudoState> sudo_scores;
    long parse_timestamp(const std::string& ts_str); // Helper

    // Cooldown maps for V1 and V3 (AUID -> last alert Unix time)
    std::unordered_map<int, long> priv_esc_cooldown;
    std::unordered_map<int, long> sensitive_cooldown;
    static constexpr long ALERT_COOLDOWN_SECS = 10;

    // Vector 1: Stateless Heuristic (SUID/SGID)
    void check_privilege_escalation(const LogEvent& event);
    
    // Vector 2: Stateful Scoring
    void check_sudo_misuse(const LogEvent& event);
    
    // Vector 3: Pattern Matching
    void check_sensitive_access(const LogEvent& event);
    
    // Helper to send alert with severity level
    void alert(const std::string& vector, const std::string& msg, const LogEvent& event, AlertSeverity severity);
};

#endif // RULES_ENGINE_H
