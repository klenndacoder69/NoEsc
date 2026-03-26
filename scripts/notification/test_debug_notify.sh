#!/bin/bash
# Debug script to test notification detection logic

echo "=== Debugging Notification System ==="
echo ""

echo "1. Current user:"
whoami
echo ""

echo "2. Logged-in graphical users:"
who | grep '(:' | awk '{print $1}' | head -n1
echo ""

echo "3. Your UID:"
id -u
echo ""

echo "4. DBUS session addresses:"
ps e -u $(whoami) | grep -o 'DBUS_SESSION_BUS_ADDRESS=[^ ]*' | head -n1
echo ""

echo "5. DISPLAY variable:"
echo $DISPLAY
echo ""

echo "6. Testing direct notify-send:"
notify-send --urgency=critical --icon=dialog-error "Direct Test" "This should work" 2>&1
echo "Result: $?"
echo ""

echo "7. Testing with DBUS export:"
DBUS_ADDR=$(ps e -u $(whoami) | grep -o 'DBUS_SESSION_BUS_ADDRESS=[^ ]*' | head -n1)
if [ -n "$DBUS_ADDR" ]; then
    echo "Found DBUS: $DBUS_ADDR"
    eval "$DBUS_ADDR" notify-send "DBUS Test" "Testing with explicit DBUS" 2>&1
    echo "Result: $?"
else
    echo "No DBUS address found!"
fi

