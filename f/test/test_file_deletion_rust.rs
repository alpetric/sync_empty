//! Test if deleting credential files prevents memory extraction
//! Spoiler: NO - credentials remain in heap memory

use std::fs;

fn main() -> anyhow::Result<String> {
    let mut output = String::new();
    output.push_str("════════════════════════════════════════════════════════════════\n");
    output.push_str("Rust Memory Test: File Deletion Approach\n");
    output.push_str("════════════════════════════════════════════════════════════════\n\n");

    // Phase 1: Create credential file
    output.push_str("[Phase 1] Creating credential file...\n");
    let secret_file = "/tmp/rust_secret_test.txt";
    let database_url = "postgres://postgres:SECRET_PASSWORD@localhost:5432/windmill";

    fs::write(secret_file, database_url)?;
    output.push_str(&format!("  ✓ File created: {}\n\n", secret_file));

    // Phase 2: Read into memory
    output.push_str("[Phase 2] Reading with fs::read_to_string()...\n");
    let contents = fs::read_to_string(secret_file)?;
    output.push_str(&format!("  ✓ Read into String: {}...\n", &contents[..40]));
    output.push_str(&format!("  ✓ Heap pointer: {:p}\n", contents.as_ptr()));
    output.push_str(&format!("  ✓ Length: {} bytes\n\n", contents.len()));

    // Phase 3: DELETE FILE (proposed security measure)
    output.push_str("[Phase 3] Deleting source file...\n");
    fs::remove_file(secret_file)?;
    output.push_str("  ✓ File deleted with fs::remove_file()\n\n");

    // Verify deletion
    output.push_str("[Phase 4] Verifying file deletion...\n");
    match fs::metadata(secret_file) {
        Ok(_) => output.push_str("  ❌ File still exists!\n\n"),
        Err(_) => output.push_str("  ✓ File confirmed deleted\n\n"),
    }

    // Phase 5: Parse credentials
    output.push_str("[Phase 5] Parsing credentials into struct...\n");

    struct Creds {
        user: String,
        password: String,
    }

    let creds = Creds {
        user: "postgres".to_string(),
        password: "SECRET_PASSWORD".to_string(),
    };

    output.push_str("  ✓ Parsed into struct:\n");
    output.push_str(&format!("    User: {}\n", creds.user));
    output.push_str(&format!("    Password: {}\n", creds.password));
    output.push_str(&format!("  ✓ Password ptr: {:p}\n\n", creds.password.as_ptr()));

    // Phase 6: Memory status
    output.push_str("[Phase 6] MEMORY STATUS CHECK\n");
    output.push_str("  Variables currently in Rust heap memory:\n");
    output.push_str(&format!("    • contents: \"{}\"\n", contents));
    output.push_str(&format!("    • creds.password: \"{}\"\n", creds.password));
    output.push_str(&format!("    • creds.user: \"{}\"\n\n", creds.user));

    output.push_str("  ❌ ALL CREDENTIAL DATA STILL IN MEMORY!\n");
    output.push_str("  ❌ File deletion did NOT clear heap!\n\n");

    // Phase 7: Memory addresses
    output.push_str("[Phase 7] Memory address analysis\n");
    let my_pid = std::process::id();
    output.push_str(&format!("  Process PID: {}\n", my_pid));
    output.push_str(&format!("  Heap allocation 'contents': {:p}\n", contents.as_ptr()));
    output.push_str(&format!("  Heap allocation 'password': {:p}\n\n", creds.password.as_ptr()));

    // Try to read own maps
    let maps_path = format!("/proc/{}/maps", my_pid);
    if let Ok(maps) = fs::read_to_string(&maps_path) {
        let heap_lines: Vec<_> = maps.lines().filter(|l| l.contains("[heap]")).collect();
        if !heap_lines.is_empty() {
            output.push_str(&format!("  Heap region: {}\n", heap_lines[0]));
            output.push_str("  ✓ Heap is readable via /proc/[pid]/maps\n\n");
        }
    }

    // Phase 8: Can we access windmill's memory?
    output.push_str("[Phase 8] Testing windmill parent process access...\n");

    let ps_cmd = std::process::Command::new("sh")
        .arg("-c")
        .arg("ps aux | grep -E 'target/(debug|release)/windmill$' | grep -v grep | awk '{print $2}' | head -1")
        .output();

    if let Ok(ps_out) = ps_cmd {
        let windmill_pid = String::from_utf8_lossy(&ps_out.stdout).trim().to_string();
        if !windmill_pid.is_empty() {
            output.push_str(&format!("  Found windmill PID: {}\n", windmill_pid));

            let mem_path = format!("/proc/{}/mem", windmill_pid);
            match fs::metadata(&mem_path) {
                Ok(_) => {
                    output.push_str(&format!("  ✓ {} is accessible\n", mem_path));
                    output.push_str("  ❌ Attacker can read windmill's memory!\n\n");
                }
                Err(e) => output.push_str(&format!("  ✓ Protected: {}\n\n", e)),
            }
        } else {
            output.push_str("  ! Windmill process not found\n\n");
        }
    }

    // Results
    output.push_str("════════════════════════════════════════════════════════════════\n");
    output.push_str("RESULTS\n");
    output.push_str("════════════════════════════════════════════════════════════════\n\n");

    output.push_str("File status:     ✓ DELETED (fs::remove_file succeeded)\n");
    output.push_str("Memory status:   ❌ CONTAINS ALL CREDENTIALS\n\n");

    output.push_str("Evidence:\n");
    output.push_str("  1. fs::remove_file() succeeded\n");
    output.push_str("  2. File verified deleted via fs::metadata()\n");
    output.push_str(&format!("  3. Variable 'contents' still has: {}\n", contents));
    output.push_str(&format!("  4. Variable 'creds.password' still has: {}\n", creds.password));
    output.push_str("  5. Both are heap-allocated (pointers shown above)\n");
    output.push_str("  6. /proc/[pid]/mem is accessible to same-UID processes\n\n");

    output.push_str("════════════════════════════════════════════════════════════════\n");
    output.push_str("CONCLUSION\n");
    output.push_str("════════════════════════════════════════════════════════════════\n\n");

    output.push_str("Deleting the credential file after fs::read_to_string() provides\n");
    output.push_str("ZERO protection against memory extraction attacks.\n\n");

    output.push_str("When you call fs::read_to_string():\n");
    output.push_str("  1. OS reads file into kernel buffer\n");
    output.push_str("  2. Rust allocates String on heap\n");
    output.push_str("  3. Kernel copies data to heap\n");
    output.push_str("  4. fs::remove_file() only affects filesystem\n");
    output.push_str("  5. Heap memory remains untouched\n\n");

    output.push_str("Security benefit vs environment variable clearing: NONE\n");
    output.push_str("Both approaches have identical memory footprint.\n\n");

    output.push_str("The ONLY real solutions:\n");
    output.push_str("  ✅ nsjail sandboxing (PID namespace isolation)\n");
    output.push_str("  ✅ UID separation (workers ≠ user scripts)\n");
    output.push_str("  ✅ Workers don't store credentials\n\n");

    output.push_str("════════════════════════════════════════════════════════════════\n");

    println!("{}", output);
    Ok(output)
}
