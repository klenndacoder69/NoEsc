#include "uds_bridge.h"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>

// Constructor:
// The ': ...' syntax is a member initializer list. It initializes members
// before the constructor body runs.
//
// We start with sock_fd_ = -1 meaning "socket not open yet".
UdsBridge::UdsBridge(const std::string &socket_path)
    : sock_fd_(-1), socket_path_(socket_path), offline_logged_(false),
      last_offline_log_secs_(0) {
  // Zero out sockaddr_un so all unused bytes are deterministic.
  std::memset(&remote_addr_, 0, sizeof(remote_addr_));
}

// Destructor:
// '~UdsBridge' means "destructor for UdsBridge".
// It runs automatically when object lifetime ends (RAII pattern).
UdsBridge::~UdsBridge() { shutdown(); }

// initialize() prepares a non-blocking Unix datagram sender socket and the
// destination address structure.
bool UdsBridge::initialize() {
  // Already initialized: nothing to do.
  if (sock_fd_ >= 0) {
    return true;
  }

  // SOCK_DGRAM means datagram (message-based) socket.
  // This matches fire-and-forget behavior without stream framing.
  int socket_type = SOCK_DGRAM;
#ifdef SOCK_NONBLOCK
  // If supported, ask kernel for non-blocking mode at socket creation.
  socket_type |= SOCK_NONBLOCK;
#endif

  // '::socket' explicitly calls the global POSIX function socket(...).
  // The leading '::' is the global namespace operator in C++.
  sock_fd_ = ::socket(AF_UNIX, socket_type, 0);
  if (sock_fd_ < 0) {
    maybe_log_offline(errno);
    return false;
  }

#ifndef SOCK_NONBLOCK
  // Fallback path for platforms without SOCK_NONBLOCK at creation time.
  // fcntl gets current flags then sets O_NONBLOCK.
  int flags = fcntl(sock_fd_, F_GETFL, 0);
  if (flags >= 0) {
    // '(void)' explicitly discards return value to silence warnings.
    (void)fcntl(sock_fd_, F_SETFL, flags | O_NONBLOCK);
  }
#endif

  // Prepare destination Unix-domain address.
  std::memset(&remote_addr_, 0, sizeof(remote_addr_));
  remote_addr_.sun_family = AF_UNIX;

  // Guard against socket path truncation.
  if (socket_path_.size() >= sizeof(remote_addr_.sun_path)) {
    std::cerr << "[!] ML Bridge Offline: socket path too long" << std::endl;
    // '::close' is the global POSIX close(...), not a class method.
    ::close(sock_fd_);
    sock_fd_ = -1;
    return false;
  }

  // Copy path into sockaddr_un buffer. One byte is reserved for null terminator.
  std::strncpy(remote_addr_.sun_path, socket_path_.c_str(),
               sizeof(remote_addr_.sun_path) - 1);
  return true;
}

// shutdown() is safe to call multiple times.
void UdsBridge::shutdown() {
  if (sock_fd_ >= 0) {
    ::close(sock_fd_);
    sock_fd_ = -1;
  }
}

// send_event() serializes one LogEvent and sends it as one datagram.
// Any failure is treated as best-effort drop; caller should continue.
void UdsBridge::send_event(const LogEvent &event) {
  // Lazy init: open socket only when first send is attempted.
  if (sock_fd_ < 0 && !initialize()) {
    return;
  }

  std::string payload = build_payload_json(event);

  // sendto(...) sends one message to remote_addr_.
  // reinterpret_cast converts sockaddr_un* to generic sockaddr* required by API.
  ssize_t sent =
      ::sendto(sock_fd_, payload.data(), payload.size(), 0,
               reinterpret_cast<const struct sockaddr *>(&remote_addr_),
               sizeof(remote_addr_));

  // Negative return means failure; inspect errno.
  if (sent < 0) {
    int errnum = errno;
    if (is_offline_error(errnum)) {
      maybe_log_offline(errnum);
    }
    return;
  }

  // static_cast enforces explicit type conversion in C++.
  // On success, reset offline flag so next offline episode can log once again.
  if (sent == static_cast<ssize_t>(payload.size())) {
    offline_logged_ = false;
  }
}

// Dump one serialized event as JSON to stdout (newline-delimited JSON).
// Used by offline conversion mode to avoid socket drops during high-throughput
// batch parsing.
void UdsBridge::dump_event_json_stdout(const LogEvent &event) const {
  std::cout << build_payload_json(event) << '\n';
}

// Classify errno values that represent offline/unavailable receiver states.
bool UdsBridge::is_offline_error(int errnum) const {
  if (errnum == EAGAIN || errnum == ENOENT || errnum == ECONNREFUSED) {
    return true;
  }
#ifdef EWOULDBLOCK
  // Some systems define EWOULDBLOCK separately from EAGAIN.
  if (errnum == EWOULDBLOCK) {
    return true;
  }
#endif
  return false;
}

// Print "ML Bridge Offline" at most once per cooldown window.
void UdsBridge::maybe_log_offline(int errnum) {
  // steady_clock is monotonic (not affected by wall-clock jumps).
  long now_secs =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count();

  if (offline_logged_ &&
      (now_secs - last_offline_log_secs_) < OFFLINE_LOG_COOLDOWN_SECS) {
    return;
  }

  offline_logged_ = true;
  last_offline_log_secs_ = now_secs;

  std::cerr << "[!] ML Bridge Offline (" << std::strerror(errnum)
            << "): dropping ML payloads" << std::endl;
}

// Build fixed payload schema expected by the ML listener.
std::string UdsBridge::build_payload_json(const LogEvent &event) const {
  // Prefer syscall string; fall back to numeric syscall_id if needed.
  std::string syscall_value = event.syscall;
  if (syscall_value.empty() && event.syscall_id >= 0) {
    syscall_value = std::to_string(event.syscall_id);
  }

  // ostringstream is used for clear, explicit JSON assembly.
  std::ostringstream json;
  json << "{"
       << "\"syscall\":\"" << escape_json(syscall_value) << "\","
       << "\"auid\":\"" << escape_json(std::to_string(event.auid))
       << "\"," << "\"euid\":\"" << escape_json(std::to_string(event.euid))
       << "\"," << "\"exe\":\"" << escape_json(event.exe) << "\","
       << "\"pid\":\"" << escape_json(std::to_string(event.pid)) << "\""
       << "}";
  return json.str();
}

// Escape JSON-sensitive characters and control bytes.
std::string UdsBridge::escape_json(const std::string &value) const {
  std::ostringstream escaped;
  // Iterate as unsigned char so values < 0x20 are handled correctly.
  for (unsigned char c : value) {
    switch (c) {
    case '"':
      escaped << "\\\"";
      break;
    case '\\':
      escaped << "\\\\";
      break;
    case '\b':
      escaped << "\\b";
      break;
    case '\f':
      escaped << "\\f";
      break;
    case '\n':
      escaped << "\\n";
      break;
    case '\r':
      escaped << "\\r";
      break;
    case '\t':
      escaped << "\\t";
      break;
    default:
      if (c < 0x20) {
        escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                << static_cast<int>(c) << std::dec;
      } else {
        escaped << static_cast<char>(c);
      }
      break;
    }
  }
  return escaped.str();
}
