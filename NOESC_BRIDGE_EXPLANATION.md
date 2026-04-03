# NoEsc Bridge Implementation Explained

## Audience and Goal
This document is written for someone with little to no background in systems programming, sockets, or machine learning pipelines.

Its goal is to explain:
- What was added
- Why each change matters
- How the parts connect together
- What is working now vs what is still a future step

---

## 1. Big Picture in Plain Language

Before this work, your daemon did this:
1. Read audit log lines
2. Parse them into fields
3. Run rule-based detection only

After this work, your daemon now does this:
1. Read audit log lines
2. Parse them into fields
3. Send a copy of selected raw fields to a Python ML listener (best-effort)
4. Continue rule-based detection exactly as before

Important: these two paths are kept separate on purpose.
- Rule Engine path = still independent and authoritative for current detection
- ML path = currently receives and buffers data only (no decisions sent back)

This separation is what enables a fair Pure Rules vs Pure ML experiment.

---

## 2. What Exactly Was Implemented

### New files
- [src/daemon/uds_bridge.h](src/daemon/uds_bridge.h)
- [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp)

### Existing files updated
- [src/daemon/main.cpp](src/daemon/main.cpp)
- [src/daemon/parser.cpp](src/daemon/parser.cpp)
- [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py)
- [CMakeLists.txt](CMakeLists.txt)
- [Makefile](Makefile)
- [README.md](README.md)

---

## 3. End-to-End Data Flow

### Step A: Daemon receives a raw audit line
In [src/daemon/main.cpp](src/daemon/main.cpp#L49), each input line is parsed.

### Step B: Parser extracts fields
In [src/daemon/parser.cpp](src/daemon/parser.cpp#L60), parse_line fills a LogEvent.
A key addition is syscall extraction into a string field at [src/daemon/parser.cpp](src/daemon/parser.cpp#L70).

Why this matters:
- ML payload contract requires syscall as a string
- Some downstream feature pipelines expect textual or string-normalized fields

### Step C: Daemon sends ML payload in parallel
In [src/daemon/main.cpp](src/daemon/main.cpp#L52), the daemon calls ml_bridge.send_event(event).

### Step D: Rule engine still runs immediately
In [src/daemon/main.cpp](src/daemon/main.cpp#L53), engine.evaluate(event) still runs right after send_event.

Why this matters:
- ML send must not delay or alter rule detection
- This preserves behavior for Pure Rules evaluation

---

## 4. The New UDS Bridge Module (C++)

### Where it is
- Interface: [src/daemon/uds_bridge.h](src/daemon/uds_bridge.h)
- Implementation: [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp)

### Core responsibilities
1. Open a Unix Domain Socket datagram sender
2. Build JSON payload from parsed event fields
3. Send payload in non-blocking mode
4. If offline/unavailable, log once and suppress repeated logs for 60 seconds

### Socket type chosen: datagram (SOCK_DGRAM)
At [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L26), socket type is datagram.

Why this matters:
- Connectionless fire-and-forget behavior
- Lower framing complexity than stream sockets
- Aligns with your decision to minimize C++ overhead

### Non-blocking behavior
Socket is created non-blocking at [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L29) and fallback non-blocking setup is applied around [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L36).

Why this matters:
- Daemon should never stall waiting on ML side
- Rule engine throughput remains protected

### Send path
The send happens in [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L66) through sendto at [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L74).

If send fails with EAGAIN, ENOENT, ECONNREFUSED (or EWOULDBLOCK), it is treated as offline at [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L89).

### Offline message rate-limiting
Offline logging logic is in [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L103).
Suppression window constant is OFFLINE_LOG_COOLDOWN_SECS in [src/daemon/uds_bridge.h](src/daemon/uds_bridge.h#L24) and currently set to 60 seconds.

Why this matters:
- Prevents stderr flood under high event rates
- Reduces IO overhead from repetitive error logs
- Keeps daemon behavior stable in offline ML mode

### JSON payload contract
Payload is built in [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L121).

Current payload shape:
{"syscall":"...","auid":"...","euid":"...","exe":"...","pid":"..."}

Why each field matters:
- syscall: operation identifier for sequence modeling
- auid: original authenticated user identity context
- euid: effective privilege level during action
- exe: program path being executed
- pid: process identity needed for per-process sequence isolation

### Safe JSON escaping
String escaping is handled in [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L136).

Why this matters:
- Prevents malformed JSON when values contain quotes, backslashes, or control characters

---

## 5. Main Daemon Integration Changes

### Initialization and lifecycle
Bridge instance creation is in [src/daemon/main.cpp](src/daemon/main.cpp#L40).
Initialization call is in [src/daemon/main.cpp](src/daemon/main.cpp#L44).
Shutdown call is in [src/daemon/main.cpp](src/daemon/main.cpp#L59).

Why this matters:
- Clear startup and teardown behavior
- Clean resource handling

### Ordering decision in loop
In [src/daemon/main.cpp](src/daemon/main.cpp#L52), send occurs before rule evaluation at [src/daemon/main.cpp](src/daemon/main.cpp#L53).

Why this matters:
- Both engines observe same parsed event stream timing
- Still no coupling because rule decisions are not included in ML payload

---

## 6. Parser Change and Its Relevance

In [src/daemon/parser.cpp](src/daemon/parser.cpp#L70), parser now stores syscall as a string.

Why this matters:
- ML payload contract explicitly includes syscall as a string
- String form can be transformed later into categorical features, tokenized sequences, or n-grams
- Avoids losing signal if downstream expects text-based processing

---

## 7. Python ML Listener Implementation

### Where it is
[src/ml_engine/model_interface.py](src/ml_engine/model_interface.py)

### What it does now
1. Binds Unix datagram socket at /tmp/noesc_ml.sock in [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py#L139)
2. Cleans stale socket file on startup in [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py#L134)
3. Receives JSON payloads and validates shape in [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py#L131)
4. Buffers events by pid and time window in SequenceBuffer at [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py#L38)
5. Prints sequence outputs and n-grams as observability output
6. Unlinks socket on shutdown in final cleanup around [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py#L191)

### Required payload fields
Defined in [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py#L20):
- syscall
- auid
- euid
- exe
- pid

Why this matters:
- Enforces your fixed payload contract
- Makes listener robust against partial/malformed sender data

### PID-aware buffering
SequenceBuffer groups events by pid in [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py#L44) and expires windows in [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py#L70).

Why this matters:
- Prevents mixing events from concurrent processes
- Enables cleaner sequential features for n-gram modeling

### Current printed outputs
- ML-SEQ lines for process-local sequence snapshots
- ML-NGRAM lines when enough sequence length exists

Why this matters:
- Gives immediate visibility that bridge + listener are receiving and structuring data correctly
- Useful before full model training/inference is integrated

---

## 8. Build System and Documentation Wiring

### CMake integration
Bridge source/header added in:
- [CMakeLists.txt](CMakeLists.txt#L12)
- [CMakeLists.txt](CMakeLists.txt#L20)

### Makefile integration
Bridge source added in:
- [Makefile](Makefile#L6)

### README compile command sync
Direct compile command now includes bridge source in:
- [README.md](README.md#L38)

Why this matters:
- Prevents build mismatch between source code and build instructions
- Keeps onboarding friction low

---

## 9. Fairness and Experimental Integrity

This implementation preserves strict separation:

### Rule engine does not consume ML outputs
There is no callback path from Python listener into rule engine evaluation flow.

### ML side does not receive rule verdicts
Payload only includes raw selected fields. No vector names, no alert levels, no rule decisions.

### Relevance
This is exactly what you need for a valid comparison:
- Pure Rules baseline
- Pure ML baseline
- No hybrid leakage during this phase

---

## 10. Operational Meaning of Common Messages

### Message: ML Bridge Offline (...): dropping ML payloads
Source: [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L117)

Meaning:
- Daemon could not send to ML socket right now
- Rule detection still continues
- Message is rate-limited to avoid spam

### Message: NoEsc ML listener bound at /tmp/noesc_ml.sock
Source: [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py#L146)

Meaning:
- Python listener is online and ready to receive datagrams

### Message: ML-SEQ ... seq=
If sequence appears empty, it typically means syscall value was missing/empty in that input event payload, not that the bridge failed.

---

## 11. Why These Choices Are Practical

### Datagram + non-blocking
Practical gain:
- Minimal sender overhead
- No connection management complexity
- No blocking impact on detector loop

Tradeoff:
- Packet delivery is best-effort, not guaranteed

### Rate-limited offline logs
Practical gain:
- Prevent stderr flood in heavy bursts
- Protects system responsiveness during ML offline periods

Tradeoff:
- You may not see every failed send event explicitly in logs

### Include pid in payload
Practical gain:
- Correct process-local sequence construction
- Avoids interleaving of unrelated process behavior

Tradeoff:
- Slightly larger payload

---

## 12. What Is Complete vs Not Complete Yet

### Complete now
- C++ bridge module
- Daemon integration
- Non-blocking datagram sending
- Offline rate-limited logging
- Python listener with pid-aware buffering
- Build and docs updates

### Not complete yet
- Trained model loading and inference logic
- Feature vector extraction pipeline for training/evaluation metrics
- Automated experiment report generation

This is expected and consistent with your phased plan.

---

## 13. Simple Mental Model

Think of the daemon as a security guard writing every event on a card.
- One copy of each card goes to the Rule Engine desk (current detector)
- Another copy is tossed through a mail slot to the ML desk (socket datagram)

If the ML desk is closed:
- Cards sent to ML may be dropped
- Security guard still keeps doing full Rule Engine work
- A warning note is shown occasionally, not nonstop

This is exactly the behavior you wanted: low overhead, no blocking, and strict experiment separation.

---

## 14. Quick Reference Map

### Core C++ flow
- Loop and send/evaluate order: [src/daemon/main.cpp](src/daemon/main.cpp#L49)
- Bridge send function: [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L66)
- Payload creation: [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L121)
- Offline suppression logic: [src/daemon/uds_bridge.cpp](src/daemon/uds_bridge.cpp#L103)

### Core Python flow
- Listener entry: [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py#L139)
- Required fields contract: [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py#L20)
- PID sequence buffering: [src/ml_engine/model_interface.py](src/ml_engine/model_interface.py#L38)

### Build wiring
- CMake: [CMakeLists.txt](CMakeLists.txt#L12)
- Makefile: [Makefile](Makefile#L6)
- README compile command: [README.md](README.md#L38)

---

## 15. Final Summary

You now have a robust first-stage data bridge from daemon to Python ML listener that is:
- Non-blocking
- Best-effort
- Rate-limited on offline errors
- Strictly separated from rule decisions
- Ready for the next stage of pure ML training and evaluation

The relevance is high: this is the infrastructure layer that makes your fair comparison architecture possible.
