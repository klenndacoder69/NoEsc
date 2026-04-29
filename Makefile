# Simple Makefile for NoEsc Daemon

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -I src/daemon
TARGET = noesc_daemon
SOURCES = src/daemon/main.cpp src/daemon/parser.cpp src/daemon/rules_engine.cpp src/daemon/uds_bridge.cpp

# Default target
all: $(TARGET)

# Build the daemon
$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES)
	@echo "Build successful! Run with: ./$(TARGET)"

# Clean up
clean:
	rm -f $(TARGET)

.PHONY: all clean
