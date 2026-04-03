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

class UdsBridge {
public:
  explicit UdsBridge(const std::string &socket_path = "/tmp/noesc_ml.sock");
  ~UdsBridge();

  bool initialize();
  void shutdown();
  void send_event(const LogEvent &event);

private:
  static constexpr long OFFLINE_LOG_COOLDOWN_SECS = 60;

  int sock_fd_;
  std::string socket_path_;
  struct sockaddr_un remote_addr_;

  bool offline_logged_;
  long last_offline_log_secs_;

  bool is_offline_error(int errnum) const;
  void maybe_log_offline(int errnum);
  std::string build_payload_json(const LogEvent &event) const;
  std::string escape_json(const std::string &value) const;
};

#endif
