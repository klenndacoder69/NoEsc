# UDS Bridge Beginner Guide (C++ Syntax + Function Walkthrough)

This guide explains the two files below in beginner-friendly detail:
- src/daemon/uds_bridge.h
- src/daemon/uds_bridge.cpp

It is written for someone who can code in general, but is new to C++ syntax and Linux socket APIs.

---

## 1. What this component does

The UDS bridge is a tiny C++ module that sends a copy of parsed audit events from the daemon to the Python ML listener.

Important behavior:
1. It uses Unix Domain Sockets (UDS), not TCP/IP.
2. It uses datagrams (message-based, fire-and-forget).
3. It is non-blocking, so it should not slow detection.
4. If the ML listener is offline, it drops payloads and logs a rate-limited warning.

In short: the bridge is a best-effort side channel, not a critical dependency.

---

## 2. Header file walkthrough: uds_bridge.h

### 2.1 Header guards

You will see:

```cpp
#ifndef UDS_BRIDGE_H
#define UDS_BRIDGE_H
...
#endif
```

Purpose:
- Prevents the compiler from including the same header multiple times in one compilation unit.
- Avoids redefinition errors.

---

### 2.2 Includes

```cpp
#include "Event.h"
#include <string>
#include <sys/un.h>
```

What each provides:
- Event.h: defines LogEvent structure used by send_event.
- string: gives std::string.
- sys/un.h: defines Unix-domain socket address struct (sockaddr_un).

---

### 2.3 Class structure

```cpp
class UdsBridge {
public:
  ...
private:
  ...
};
```

C++ access levels:
- public: callable from other files/modules.
- private: internal implementation details.

---

### 2.4 Constructor and explicit

```cpp
explicit UdsBridge(const std::string &socket_path = "/tmp/noesc_ml.sock");
```

Syntax explained:
- constructor has same name as class.
- default argument means you can write UdsBridge() and still get /tmp/noesc_ml.sock.
- const std::string &: pass by reference (no copy), and const prevents modification.
- explicit prevents accidental implicit conversions.

Why explicit matters:
- Without explicit, C++ could allow surprising conversions like passing a string where UdsBridge object is expected.

---

### 2.5 Destructor and tilde syntax

```cpp
~UdsBridge();
```

This is the destructor.

What the ~ means:
- In C++, ~ClassName declares the function that runs when object lifetime ends.
- It is mainly used for cleanup (files, sockets, memory, locks, etc.).

In this module:
- destructor calls shutdown() so socket gets closed automatically.

---

### 2.6 Public API functions

```cpp
bool initialize();
void shutdown();
void send_event(const LogEvent &event);
```

Roles:
- initialize: open/configure socket.
- shutdown: close/reset socket.
- send_event: serialize one LogEvent and send it.

---

### 2.7 Internal constants and fields

```cpp
static constexpr long OFFLINE_LOG_COOLDOWN_SECS = 60;
```

Syntax explained:
- static: belongs to class-level logic (single value definition intent).
- constexpr: compile-time constant.
- long: integer type.

Purpose:
- prevents repeating offline warning too often.

---

```cpp
int sock_fd_;
std::string socket_path_;
struct sockaddr_un remote_addr_;
bool offline_logged_;
long last_offline_log_secs_;
```

Field meanings:
- sock_fd_: POSIX file descriptor for socket. -1 means not open.
- socket_path_: destination path, usually /tmp/noesc_ml.sock.
- remote_addr_: destination address passed to sendto.
- offline_logged_: remembers whether offline warning was recently printed.
- last_offline_log_secs_: last warning timestamp.

Naming note:
- trailing underscore is a common C++ style for member fields.

---

### 2.8 Private helper functions

```cpp
bool is_offline_error(int errnum) const;
void maybe_log_offline(int errnum);
std::string build_payload_json(const LogEvent &event) const;
std::string escape_json(const std::string &value) const;
```

What const at end means:
- member function promises not to modify object state.
- useful for read-only helpers.

---

## 3. Source file walkthrough: uds_bridge.cpp

### 3.1 Includes

```cpp
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>
```

Why needed:
- cerrno: errno constants and error reporting context.
- chrono: monotonic time for cooldown logic.
- cstring: memset, strncpy, strerror.
- fcntl.h: fcntl for O_NONBLOCK fallback.
- iomanip + sstream: JSON string construction/formatting.
- sys/socket.h + unistd.h: socket/sendto/close POSIX APIs.

---

### 3.2 Constructor implementation

```cpp
UdsBridge::UdsBridge(const std::string &socket_path)
    : sock_fd_(-1), socket_path_(socket_path), offline_logged_(false),
      last_offline_log_secs_(0) {
  std::memset(&remote_addr_, 0, sizeof(remote_addr_));
}
```

Important C++ syntax:

#### A) UdsBridge::
- :: here is scope resolution operator.
- UdsBridge::Function means function belongs to class UdsBridge.

#### B) Member initializer list (: ...)
- This initializes members before constructor body.
- Preferred and often faster/safer than assignment in body.

#### C) std::memset
- fills memory with a byte value (0 here).
- used for C structs like sockaddr_un to avoid garbage bytes.

---

### 3.3 Destructor implementation

```cpp
UdsBridge::~UdsBridge() { shutdown(); }
```

Why this is good:
- automatic cleanup even if caller forgets shutdown.
- classic RAII style.

RAII idea:
- Resource Acquisition Is Initialization.
- object lifetime controls resource lifetime.

---

### 3.4 initialize()

```cpp
bool UdsBridge::initialize() {
  if (sock_fd_ >= 0) return true;
  ...
}
```

Step-by-step purpose:
1. If already open, do nothing.
2. Build socket type flags.
3. Create socket with AF_UNIX + SOCK_DGRAM + non-blocking.
4. Fallback to fcntl non-blocking if needed.
5. Fill destination address struct.
6. Validate path length.
7. Copy path into remote_addr_.

#### Why this line uses ::socket

```cpp
sock_fd_ = ::socket(AF_UNIX, socket_type, 0);
```

- socket(...) is a global POSIX function.
- leading :: means "look in global namespace".
- This avoids any ambiguity with class/member names.

Parameter meaning:
- AF_UNIX: local machine Unix socket family.
- socket_type: datagram + maybe non-block flag.
- 0: default protocol for this family/type.

Return value:
- >= 0 means success (file descriptor).
- < 0 means failure and errno is set.

#### Why fcntl fallback exists

Some platforms may not define SOCK_NONBLOCK at socket creation time. If that macro is unavailable, code manually sets O_NONBLOCK after creation.

---

### 3.5 shutdown()

```cpp
void UdsBridge::shutdown() {
  if (sock_fd_ >= 0) {
    ::close(sock_fd_);
    sock_fd_ = -1;
  }
}
```

Purpose:
- close system resource cleanly.
- reset state to not-open.

Again, ::close means global POSIX close function.

---

### 3.6 send_event()

Main logic:
1. Ensure initialized (lazy init).
2. Build JSON payload string.
3. Send one datagram with sendto.
4. Handle failure with errno classification.
5. Clear offline flag after successful send.

Key line:

```cpp
ssize_t sent = ::sendto(sock_fd_, payload.data(), payload.size(), 0,
                        reinterpret_cast<const struct sockaddr *>(&remote_addr_),
                        sizeof(remote_addr_));
```

Syntax explained:
- ssize_t: signed size type used by many POSIX calls.
- payload.data(): raw pointer to bytes of string.
- payload.size(): byte count.
- reinterpret_cast<...>: explicit C++ cast between pointer types.

Why reinterpret_cast is needed:
- sendto expects pointer type const sockaddr*.
- our concrete type is sockaddr_un*.
- cast tells compiler we intentionally view same memory as generic sockaddr.

Failure handling:
- sent < 0 means error; inspect errno.
- on recognized offline errors, log rate-limited warning.
- return without throwing or blocking.

Success handling:
- if full payload sent, set offline_logged_ = false.
- this allows future offline episode to log once again.

---

### 3.7 is_offline_error()

Checks whether errno indicates receiver unavailable or temporary send unavailability.

Handled values:
- EAGAIN
- ENOENT
- ECONNREFUSED
- EWOULDBLOCK (if defined)

Why this exists:
- centralizes policy of what should trigger "offline" warning.

---

### 3.8 maybe_log_offline()

Core idea:
- print warning now only if cooldown window has passed.

Time logic:
- uses std::chrono::steady_clock.
- steady_clock is monotonic (not affected by manual time changes/NTP jumps).

Behavior:
1. Compute current monotonic seconds.
2. If already logged and cooldown not elapsed, return.
3. Update last log time and print warning.

---

### 3.9 build_payload_json()

Builds exact fixed schema:

```json
{"syscall":"...","auid":"...","euid":"...","exe":"...","pid":"..."}
```

Important details:
- Prefers event.syscall text.
- Falls back to event.syscall_id if string missing.
- Uses escape_json on all values to keep JSON valid.

Why using ostringstream:
- simple and explicit string assembly.
- avoids manual char buffer management.

---

### 3.10 escape_json()

Purpose:
- convert problematic characters to JSON-safe escape sequences.

Examples:
- " becomes \"
- backslash becomes \\
- newline becomes \n
- control chars < 0x20 become \u00XX

Why loop uses unsigned char:
- avoids sign-related issues for byte values.

---

## 4. C++ syntax mini-cheat sheet from this file

### 4.1 Scope resolution operator ::
Used in two ways:
1. Class scope: UdsBridge::send_event
2. Global scope: ::socket, ::sendto, ::close

Meaning:
- qualify exactly where a symbol should be resolved.

### 4.2 Destructor syntax ~ClassName
- Declares cleanup function called when object dies.
- Not bitwise NOT operator in this context.

### 4.3 Reference parameter const T &
- Pass by reference (no copy).
- const means read-only.
- common for performance + safety.

### 4.4 explicit keyword
- blocks automatic implicit conversion for one-argument constructors.

### 4.5 static constexpr
- class-level constant known at compile time.

### 4.6 Casts used
- reinterpret_cast: low-level pointer conversion.
- static_cast: safe explicit numeric/type conversion.

### 4.7 Preprocessor directives
- #ifdef / #ifndef / #endif are compile-time conditional blocks.
- used for portability across environments.

---

## 5. Why this bridge is safe for your rule engine path

Safety properties:
1. Non-blocking sender socket.
2. Best-effort send with immediate return on failure.
3. No retries inside hot detection loop.
4. Offline log suppression prevents stderr flood.
5. Rule engine evaluation continues independently.

Result:
- ML path availability should not break or stall rule detections.

---

## 6. Short function purpose table

| Function | Purpose | Why it exists |
|---|---|---|
| UdsBridge(...) | set initial state and target socket | predictable startup |
| ~UdsBridge() | auto-cleanup | resource safety |
| initialize() | open/config socket and destination | one-time setup |
| shutdown() | close socket and reset fd | clean teardown |
| send_event(...) | serialize + send one datagram | bridge runtime behavior |
| is_offline_error(...) | classify errno | consistent error policy |
| maybe_log_offline(...) | rate-limit offline warnings | avoid stderr spam |
| build_payload_json(...) | build fixed ML payload schema | contract enforcement |
| escape_json(...) | sanitize values for JSON | payload correctness |

---

## 7. Common beginner questions

### Q1) Why not use TCP?
Because this path is intentionally lightweight and best-effort. Datagram UDS avoids connection/session management and stream framing.

### Q2) Why no exceptions on send failure?
The bridge is not mission-critical for current rule detection. Throwing would risk disrupting main processing.

### Q3) Why check socket path length?
sockaddr_un has fixed-size sun_path buffer. Oversized paths would overflow/truncate and cause undefined behavior or wrong addressing.

### Q4) Why reset offline_logged_ after successful send?
So a new offline episode can produce one warning again. Otherwise warning could remain permanently suppressed.

### Q5) Why cooldown by time, not by count?
Time-based suppression is stable under both low and high traffic rates.

---

## 8. One mental model

Think of UdsBridge as a non-blocking "mail drop".
- initialize() opens the mailbox slot.
- send_event() drops a message in.
- if receiving office is closed, message is dropped and warning appears occasionally.
- rule engine work keeps running regardless.

---

## 9. Where to read next in your codebase

1. src/daemon/main.cpp
Why: shows exactly where send_event() runs relative to engine.evaluate().

2. src/ml_engine/model_interface.py
Why: shows how payload is received, normalized, and buffered by pid.

3. src/daemon/parser.cpp
Why: shows where payload fields are extracted from raw audit lines.
