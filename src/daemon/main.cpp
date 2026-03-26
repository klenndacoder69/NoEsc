#include "parser.h"
#include "rules_engine.h"
#include <csignal>
#include <iostream>
#include <string>
#include <unistd.h>

// Global flag for graceful shutdown
volatile sig_atomic_t running = 1;

void signal_handler(int) { running = 0; }

int main() {
  // Register signal handlers
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  // Initialize components
  RulesEngine engine;
  LogEvent event;
  std::string line;

  // Optimize Standard I/O operations for speed
  std::ios_base::sync_with_stdio(false);
  std::cin.tie(NULL);

  // Main Event Loop: Read from STDIN (Audit Dispatcher)
  while (running && std::getline(std::cin, line)) {
    try {
      // Parse the raw line
      if (AuditParser::parse_line(line, event)) {
        // DEBUG: Print parsed event fields
        // std::cout << "[DEBUG] Parsed Event: "
        //           << "Type=" << event.type << " Syscall=" << event.syscall_id
        //           << " AUID=" << event.auid << " EXE=" << event.exe
        //           << " Key=" << event.key << std::endl;

        // Heuristic Check
        engine.evaluate(event);

        // TODO: ML Engine Handoff
        // e.g. write to named pipe or shared memory
      }
    } catch (const std::exception &e) {
      std::cerr << "[!] Error processing line: " << e.what() << std::endl;
    }
  }

  return 0;
}
