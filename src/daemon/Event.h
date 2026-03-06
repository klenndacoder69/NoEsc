// Event.h central data structure (or the schema) containing the specifcs of an
// audit log

#ifndef EVENT_H
#define EVENT_H

#include <string>

/**
 * LogEvent
 * Represents a parsed audit event structure based on Table I of the NoEsc
 * paper. This structure holds the essential fields required for both Heuristic
 * and ML detection.
 */
struct LogEvent {
  // Meta Information
  std::string raw_log;   // The original raw log line
  std::string timestamp; // Event timestamp
  std::string serial;    // Event serial number

  // Core Fields (Table I)
  std::string type;    // Event Type (e.g., SYSCALL, EXECVE)
  int syscall_id;      // Numeric syscall ID (from 'syscall=')
  std::string syscall; // Resolved syscall name (optional/resolved later)

  // User Context
  int auid;  // Audit User ID (Original Login User)
  int euid;  // Effective User ID (Current Privilege)
  int uid;   // Real User ID
  int suid;  // Saved User ID
  int fsuid; // File System User ID

  // Process Context
  int pid;   // Process ID
  int ppid;  // Parent Process ID

  // Execution Context
  std::string exe;       // Path to executable
  std::string cwd;       // Current working directory
  std::string comm;      // Command name (often truncated)
  std::string proctitle; // Full command line (if available in PROCTITLE record)
  std::string a0;        // Argument 0 (often command or file path)
  std::string a1;        // Argument 1
  std::string a2;        // Argument 2

  // Filter Key
  std::string key; // The audit rule key (e.g., "benign_exec", "priv_esc")

  // Default Constructor
  LogEvent()
      : syscall_id(-1), auid(-1), euid(-1), uid(-1), suid(-1), fsuid(-1), pid(-1), ppid(-1) {}
};

#endif // EVENT_H
