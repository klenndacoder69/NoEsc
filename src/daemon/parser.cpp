/*
 * NoEsc Parser Implementation
 *
 * The parser extracts the values needed and populates the LogEvent data
 * structure.
 *
 * sample audit log used as reference:
 * type=SYSCALL msg=audit(1764182128.048:665): arch=c000003e syscall=59
 * success=yes exit=0 a0=55f7bda33af0 a1=55f7bd77e110 a2=55f7bda238e0 a3=8
 * items=2 ppid=265555 pid=265556 auid=1000 uid=1000 gid=1000 euid=0 suid=0
 * fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts3 ses=3 comm="find"
 * exe="/usr/bin/find" key="find_executions"ARCH=x86_64 SYSCALL=execve
 * AUID="swuffles" UID="swuffles" GID="swuffles" EUID="root" SUID="root"
 * FSUID="root" EGID="swuffles" SGID="swuffles" FSGID="swuffles"
 *
 *
 *
 *
 * */

#include "parser.h"
#include <algorithm>
#include <iostream>

std::string AuditParser::extract_value(const std::string &line,
                                       const std::string &key) {
  std::string search = key + "=";
  size_t pos = line.find(search);
  if (pos == std::string::npos)
    return "";

  pos += search.length();

  if (pos < line.length() && line[pos] == '"') {
    pos++;
    size_t end = line.find('"', pos);
    if (end == std::string::npos)
      return ""; // EOL/error
    return line.substr(pos, end - pos);
  } else {
    size_t end = line.find(' ', pos);
    if (end == std::string::npos)
      end = line.length();
    return line.substr(pos, end - pos);
  }
}

int AuditParser::extract_int(const std::string &line, const std::string &key) {
  std::string val = extract_value(line, key);
  if (val.empty())
    return -1;
  try {
    return std::stoi(val);
  } catch (...) {
    return -1;
  }
}

// main function
bool AuditParser::parse_line(const std::string &line, LogEvent &event) {
  if (line.empty())
    return false;

  event.raw_log = line;

  event.type = extract_value(line, "type");
  if (event.type.empty())
    return false;

  event.syscall = extract_value(line, "syscall");
  event.syscall_id = extract_int(line, "syscall");
  event.auid = extract_int(line, "auid");
  event.euid = extract_int(line, "euid");
  event.uid = extract_int(line, "uid");
  event.suid = extract_int(line, "suid");
  event.fsuid = extract_int(line, "fsuid");
  event.pid = extract_int(line, "pid");
  event.ppid = extract_int(line, "ppid");

  event.exe = extract_value(line, "exe");
  event.key = extract_value(line, "key");
  event.comm = extract_value(line, "comm");

  event.a0 = extract_value(line, "a0");
  event.a1 = extract_value(line, "a1");
  event.a2 = extract_value(line, "a2");
  event.res = extract_value(line, "res");
  event.success = extract_value(line, "success");

  // Timestamp extraction (format: msg=audit(12345.678:123):)
  // This is slightly weirder as it's inside msg=audit(...)
  size_t msg_pos = line.find("msg=audit(");
  if (msg_pos != std::string::npos) {
    size_t start = msg_pos + 10;
    size_t end = line.find("):", start);
    if (end != std::string::npos) {
      std::string time_serial = line.substr(start, end - start);
      size_t colon = time_serial.find(':');
      if (colon != std::string::npos) {
        event.timestamp = time_serial.substr(0, colon);
        event.serial = time_serial.substr(colon + 1);
      }
    }
  }

  return true;
}
