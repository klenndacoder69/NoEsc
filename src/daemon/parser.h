/*
 * NoEsc - Audit Log Parser
 *
 * Stateless parser for auditd event streams.
 * Extracts key fields from audit log strings without state aggregation.
 *
 * Supported Event Types:
 *   - SYSCALL (process execution, syscall data)
 *   - USER_CMD (sudo commands)
 *   - USER_AUTH (authentication attempts)
 *
 * Known Limitation:
 *   PATH records (containing filenames) are not linked to SYSCALL records.
 *   Use audit keys and event IDs for forensic correlation.
 */

#ifndef PARSER_H
#define PARSER_H

#include "Event.h"
#include <string>

class AuditParser {
public:
  static bool parse_line(const std::string &line, LogEvent &event);

private:
  static std::string extract_value(const std::string &line, const std::string &key);
  static int extract_int(const std::string &line, const std::string &key);
};

#endif
