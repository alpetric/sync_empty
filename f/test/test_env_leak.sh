#!/bin/bash
# Test script to check if DATABASE_URL is still accessible in /proc/*/environ

echo "=== Testing /proc/1/environ ==="
if cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -i "DATABASE_URL"; then
    echo "❌ VULNERABLE: Found DATABASE_URL in /proc/1/environ"
else
    echo "✅ SECURE: DATABASE_URL not found in /proc/1/environ"
fi

echo ""
echo "=== Testing /proc/self/environ ==="
if cat /proc/self/environ 2>/dev/null | tr '\0' '\n' | grep -i "DATABASE_URL"; then
    echo "❌ VULNERABLE: Found DATABASE_URL in /proc/self/environ"
else
    echo "✅ SECURE: DATABASE_URL not found in /proc/self/environ"
fi

echo ""
echo "=== Testing parent process environ ==="
PPID=$(ps -o ppid= -p $$)
if cat /proc/$PPID/environ 2>/dev/null | tr '\0' '\n' | grep -i "DATABASE_URL"; then
    echo "❌ VULNERABLE: Found DATABASE_URL in parent /proc/$PPID/environ"
else
    echo "✅ SECURE: DATABASE_URL not found in parent process"
fi

echo ""
echo "=== Checking all ancestor processes ==="
current_pid=$$
found=0
while [ $current_pid -gt 1 ]; do
    parent_pid=$(ps -o ppid= -p $current_pid | tr -d ' ')
    if [ -z "$parent_pid" ] || [ "$parent_pid" = "0" ]; then
        break
    fi

    if cat /proc/$parent_pid/environ 2>/dev/null | tr '\0' '\n' | grep -qi "DATABASE_URL"; then
        echo "❌ VULNERABLE: Found DATABASE_URL in ancestor process PID $parent_pid"
        found=1
        break
    fi

    current_pid=$parent_pid
done

if [ $found -eq 0 ]; then
    echo "✅ SECURE: DATABASE_URL not found in any ancestor process"
fi

echo ""
echo "=== Environment variables visible to this script ==="
env | grep -i database || echo "No DATABASE_URL in current environment"
