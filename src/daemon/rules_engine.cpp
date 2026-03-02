#include "rules_engine.h"
#include <iostream>

void RulesEngine::evaluate(const LogEvent& event) {
    // Only process SYSCALL records for heuristic checks currently
    // In a full implementation, we would aggregate SYSCALL + EXECVE + PATH
    if (event.type != "SYSCALL") return;

    check_privilege_escalation(event);
    check_sensitive_access(event);
    // check_sudo_misuse(event); // TODO: Implement stateful logic
}

void RulesEngine::check_privilege_escalation(const LogEvent& event) {
    // Heuristic 1: Root Escalation (SUID/SGID Abuse)
    // REVISED Logic (Strict Whitelist - Stronger than Paper):
    // Alert if:
    // 1. auid != 0 (Non-root user)
    // 2. euid == 0 (Becomes Root)
    // 3. exe is NOT in a standard system binary directory (/bin, /usr/bin, /sbin, /usr/sbin)
    
    if (event.euid == 0 && event.auid != 0 && event.auid != -1) {
        bool is_standard_path = false;
        
        // Check against Standard System Paths
        // Handles unquoted paths
        if (event.exe.find("/bin/") == 0) is_standard_path = true;
        else if (event.exe.find("/usr/bin/") == 0) is_standard_path = true;
        else if (event.exe.find("/sbin/") == 0) is_standard_path = true;
        else if (event.exe.find("/usr/sbin/") == 0) is_standard_path = true;
        
        // Handles quoted paths (parser might leave quotes)
        else if (event.exe.find("\"/bin/") == 0) is_standard_path = true;
        else if (event.exe.find("\"/usr/bin/") == 0) is_standard_path = true;
        else if (event.exe.find("\"/sbin/") == 0) is_standard_path = true;
        else if (event.exe.find("\"/usr/sbin/") == 0) is_standard_path = true;
        
        // System Library Paths (for legitimate daemons like systemd-executor, gdm-session-worker)
        else if (event.exe.find("/usr/lib/") == 0) is_standard_path = true;
        else if (event.exe.find("\"/usr/lib/") == 0) is_standard_path = true;
        else if (event.exe.find("/usr/libexec/") == 0) is_standard_path = true;
        else if (event.exe.find("\"/usr/libexec/") == 0) is_standard_path = true;

        // Allow Student Sandbox Directory (Academic Use Case)
        else if (event.exe.find("/opt/student_sandbox/") == 0) is_standard_path = true;
        else if (event.exe.find("\"/opt/student_sandbox/") == 0) is_standard_path = true;

        if (!is_standard_path) {
            std::string msg = "SUID Abuse Detected! User " + std::to_string(event.auid) +
                              " escalated to ROOT via NON-STANDARD binary: " + event.exe;
            alert("PrivilegeEscalation", msg, event);
        }
    }
}

void RulesEngine::check_sensitive_access(const LogEvent& event) {
    // Heuristic 3: Sensitive File Tampering (Pattern Matching)
    // Keys: "identitychange", "sudochange" (from harvest_logs.sh)
    // We removed "perm" to avoid noise from generic chmod calls.
    
    bool is_sensitive_key = (event.key.find("identitychange") != std::string::npos) ||
                            (event.key.find("sudochange") != std::string::npos);

    if (is_sensitive_key) {
        // Logic: Alert ONLY if the process performing the change is NOT running as Root (EUID != 0)
        // Root is allowed to change these files. Normal users are not.
        if (event.euid != 0) {
            std::string msg = "Unauthorized Modification Attempt! Non-Root User (EUID=" + 
                              std::to_string(event.euid) + ") modified a critical file.";
            alert("SensitiveTampering", msg, event);
        }
    }
}

void RulesEngine::check_sudo_misuse(const LogEvent& event) {
    // Placeholder for Vector 2
}

void RulesEngine::alert(const std::string& vector, const std::string& msg, const LogEvent& event) {
    // In a real daemon, this might write to syslog or a separate alert log.
    // Since we are reading from STDIN (auditd), we must NOT write to STDOUT if it feeds back into auditd
    // (though audispd plugins usually have separate STDOUT/STDERR).
    // Writing to STDERR is safe for debugging.
    std::cerr << "[!] NoEsc ALERT [" << vector << "]: " << msg 
              << " (exe=" << event.exe << " auid=" << event.auid << ")" << std::endl;
}
