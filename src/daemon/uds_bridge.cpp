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

UdsBridge::UdsBridge(const std::string &socket_path)
    : sock_fd_(-1), socket_path_(socket_path), offline_logged_(false),
      last_offline_log_secs_(0) {
  std::memset(&remote_addr_, 0, sizeof(remote_addr_));
}

UdsBridge::~UdsBridge() { shutdown(); }

bool UdsBridge::initialize() {
  if (sock_fd_ >= 0) {
    return true;
  }

  int socket_type = SOCK_DGRAM;
#ifdef SOCK_NONBLOCK
  socket_type |= SOCK_NONBLOCK;
#endif

  sock_fd_ = ::socket(AF_UNIX, socket_type, 0);
  if (sock_fd_ < 0) {
    maybe_log_offline(errno);
    return false;
  }

#ifndef SOCK_NONBLOCK
  int flags = fcntl(sock_fd_, F_GETFL, 0);
  if (flags >= 0) {
    (void)fcntl(sock_fd_, F_SETFL, flags | O_NONBLOCK);
  }
#endif

  std::memset(&remote_addr_, 0, sizeof(remote_addr_));
  remote_addr_.sun_family = AF_UNIX;

  if (socket_path_.size() >= sizeof(remote_addr_.sun_path)) {
    std::cerr << "[!] ML Bridge Offline: socket path too long" << std::endl;
    ::close(sock_fd_);
    sock_fd_ = -1;
    return false;
  }

  std::strncpy(remote_addr_.sun_path, socket_path_.c_str(),
               sizeof(remote_addr_.sun_path) - 1);
  return true;
}

void UdsBridge::shutdown() {
  if (sock_fd_ >= 0) {
    ::close(sock_fd_);
    sock_fd_ = -1;
  }
}

void UdsBridge::send_event(const LogEvent &event) {
  if (sock_fd_ < 0 && !initialize()) {
    return;
  }

  std::string payload = build_payload_json(event);

  ssize_t sent =
      ::sendto(sock_fd_, payload.data(), payload.size(), 0,
               reinterpret_cast<const struct sockaddr *>(&remote_addr_),
               sizeof(remote_addr_));

  if (sent < 0) {
    int errnum = errno;
    if (is_offline_error(errnum)) {
      maybe_log_offline(errnum);
    }
    return;
  }

  if (sent == static_cast<ssize_t>(payload.size())) {
    offline_logged_ = false;
  }
}

bool UdsBridge::is_offline_error(int errnum) const {
  if (errnum == EAGAIN || errnum == ENOENT || errnum == ECONNREFUSED) {
    return true;
  }
#ifdef EWOULDBLOCK
  if (errnum == EWOULDBLOCK) {
    return true;
  }
#endif
  return false;
}

void UdsBridge::maybe_log_offline(int errnum) {
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

std::string UdsBridge::build_payload_json(const LogEvent &event) const {
  std::string syscall_value = event.syscall;
  if (syscall_value.empty() && event.syscall_id >= 0) {
    syscall_value = std::to_string(event.syscall_id);
  }

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

std::string UdsBridge::escape_json(const std::string &value) const {
  std::ostringstream escaped;
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
