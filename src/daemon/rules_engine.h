#ifndef RULES_ENGINE_H
#define RULES_ENGINE_H

#include "Event.h"
#include <string>

class RulesEngine {
public:
    /**
     * Evaluates a single parsed log event against heuristic rules.
     */
    void evaluate(const LogEvent& event);

private:
    // Vector 1: Stateless Heuristic (SUID/SGID)
    void check_privilege_escalation(const LogEvent& event);
    
    // Vector 2: Stateful Scoring (Placeholder)
    void check_sudo_misuse(const LogEvent& event);
    
    // Vector 3: Pattern Matching
    void check_sensitive_access(const LogEvent& event);
    
    // Helper to send alert (currently logs to stderr)
    void alert(const std::string& vector, const std::string& msg, const LogEvent& event);
};

#endif // RULES_ENGINE_H
