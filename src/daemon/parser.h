#ifndef PARSER_H
#define PARSER_H

#include "Event.h"
#include <string>

class AuditParser {
public:
  /**
   * Parses a raw audit log string into a LogEvent structure.
   * @param line The raw string from STDIN.
   * @param event Reference to the event object to populate.
   * @return true if parsing was successful and event is relevant, false
   * otherwise.
   */
  static bool parse_line(const std::string &line, LogEvent &event);

private:
  /**
   * Extracts a string value for a given key.
   * Handles unquoted and quoted values (basic support).
   */
  static std::string extract_value(const std::string &line,
                                   const std::string &key);

  /**
   * Extracts an integer value for a given key.
   * Returns -1 if key not found or invalid.
   */
  static int extract_int(const std::string &line, const std::string &key);
};

#endif // PARSER_H
