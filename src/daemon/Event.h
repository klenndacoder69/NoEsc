// Event.h central data structure (or the schema) containing the specifcs of an
// audit log

#ifndef EVENT_H
#define EVENT_H

#include <string>

/*
 * The LogEvent data structure contains the fields which include the necessary
 * things that the engine needs
 * */

struct LogEvent {

  // meta information
  std::string raw_log;
  std::string timestamp;
  std::string serial; // used to grp logs

  // These are the core fields that we need to identify what kind of events are
  // logged
  std::string type;    // Event Type (e.g., SYSCALL, EXECVE)
  int syscall_id;      // This depends on the archi, not really gonna be used
                       // thoroughly but to ensure that we know according to its
                       // archi.
  std::string syscall; // Resolved syscall name
                       // (optional/resolved later)

  // These details are used to identify "WHO" performed the operations
  int auid; // auid/euid/uid>=1000(user) : auid/euid=0(root)
  int euid;
  int uid;
  int suid; // saved id
  int fsuid;

  // Details to check what program was executed and where it was executed
  int pid;  // "what" was executed
  int ppid; // "where" was it executed

  // Supporting details of what was executed

  std::string exe;
  std::string cwd;
  std::string comm;
  std::string proctitle; 
  std::string a0;
  std::string a1;
  std::string a2;

  // res is used when authentication is a success or failure
  std::string res;

  // success or failure of the program execution
  std::string success;

  // keys
  std::string key;

  LogEvent()
      : syscall_id(-1), auid(-1), euid(-1), uid(-1), suid(-1), fsuid(-1),
        pid(-1), ppid(-1) {}
};

#endif // EVENT_H
