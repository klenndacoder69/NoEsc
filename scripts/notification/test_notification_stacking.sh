#!/bin/bash
# Test: Do multiple simultaneous notifications stack or overlay?

echo "╔════════════════════════════════════════════════════════╗"
echo "║       Notification Stacking Test (3 at once)          ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Sending 3 notifications with 0ms delay between them..."
echo ""

# Test direct notify-send first
notify-send --urgency=critical --icon=dialog-error "[NoEsc Test] Alert 1" "SUID Abuse - /tmp/evil1" &
notify-send --urgency=critical --icon=dialog-error "[NoEsc Test] Alert 2" "File Tampering - /etc/shadow" &
notify-send --urgency=critical --icon=dialog-warning "[NoEsc Test] Alert 3" "Sudo Misuse - Score 20/20" &

wait

echo "✓ 3 notifications sent simultaneously"
echo ""
echo "════════════════════════════════════════════════════════"
echo "What did you see?"
echo ""
echo "Option A: All 3 visible at once (stacked vertically)"
echo "Option B: Only saw the last one (overlayed/replaced)"
echo "Option C: Saw them flash by quickly one-by-one"
echo "════════════════════════════════════════════════════════"

