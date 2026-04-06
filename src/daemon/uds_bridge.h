/*
 * NoEsc UDS Bridge
 *
 * Sends parsed audit events to the ML side over a non-blocking Unix domain
 * datagram socket. This path is best-effort and must never block rule-based
 * detection.
 */

#ifndef UDS_BRIDGE_H
#define UDS_BRIDGE_H

#include "Event.h"
#include <string>
#include <sys/un.h>

// UdsBridge forwards parsed daemon events to the Python ML process.
//
// Design goals:
// 1) Never block or slow down the rule engine path.
// 2) Best-effort delivery only (drop on failure, do not retry inline).
// 3) Keep logging controlled when ML listener is offline.
class UdsBridge {
public:
  // Constructor:
  // - 'explicit' prevents accidental implicit conversion from std::string.
  // - Default target socket path is /tmp/noesc_ml.sock.
  explicit UdsBridge(const std::string &socket_path = "/tmp/noesc_ml.sock");

  // Destructor (~ClassName syntax): runs automatically when object goes out of
  // scope. We use it to ensure shutdown() is called and file descriptors close.
  ~UdsBridge();

  // Opens/configures the non-blocking Unix datagram sender socket.
  // Safe to call repeatedly; if already initialized it returns true.
  bool initialize();

  // Closes the socket if open and resets internal state.
  void shutdown();

  // Sends one event payload to the ML listener in best-effort mode.
  // Any send failure is handled internally; caller should continue processing.
  void send_event(const LogEvent &event);

  // Offline dataset mode helper:
  // Serialize one event and emit it as a single JSON line to stdout.
  // This path does not require socket initialization.
  void dump_event_json_stdout(const LogEvent &event) const;

private:
  // Minimum interval between repeated "ML Bridge Offline" stderr messages.
  static constexpr long OFFLINE_LOG_COOLDOWN_SECS = 60;

  // POSIX socket file descriptor.
  // -1 means "not opened/initialized".
  int sock_fd_;

  // Filesystem path of destination Unix socket.
  std::string socket_path_;

  // Destination address used by sendto().
  struct sockaddr_un remote_addr_;

  // True after an offline message was emitted during the current offline span.
  bool offline_logged_;

  // Timestamp (steady clock seconds) of the last offline log emission.
  long last_offline_log_secs_;

  // Classifies errno values that indicate the ML listener is unavailable or
  // temporarily not writable.
  bool is_offline_error(int errnum) const;

  // Emits a rate-limited offline message to stderr.
  void maybe_log_offline(int errnum);

  // Builds fixed JSON contract payload:
  // {"syscall":"...","auid":"...","euid":"...","exe":"...","pid":"...","timestamp":"..."}
  std::string build_payload_json(const LogEvent &event) const;

  // Escapes characters so strings are valid JSON values.
  std::string escape_json(const std::string &value) const;
};

#endif
