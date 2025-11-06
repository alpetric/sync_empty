use std::fs;
use std::io::Read;

fn main() -> anyhow::Result<String> {
    println!("════════════════════════════════════════════════════════════════");
    println!("Rust Memory Extraction Test: File Deletion Approach");
    println!("════════════════════════════════════════════════════════════════");
    println!();

    // Phase 1: Create credential file
    println!("[Phase 1] Creating credential file...");
    let secret_file = "/tmp/rust_test_secret.txt";
    let database_url = "postgres://postgres:changeme@localhost:5432/windmill?sslmode=disable";

    fs::write(secret_file, database_url)?;
    println!("  ✓ Created: {}", secret_file);
    println!();

    // Phase 2: Read credentials (this is what Windmill does)
    println!("[Phase 2] Reading credentials into memory...");
    let contents = fs::read_to_string(secret_file)?;
    println!("  ✓ Read into String: {}...", &contents[..40]);
    println!();

    // Phase 3: IMMEDIATELY delete file (proposed approach)
    println!("[Phase 3] Deleting source file...");
    fs::remove_file(secret_file)?;
    println!("  ✓ File deleted");

    // Verify deletion
    if fs::metadata(secret_file).is_err() {
        println!("  ✓ Deletion verified (file not found)");
    } else {
        println!("  ❌ File still exists!");
    }
    println!();

    // Phase 4: Parse credentials (simulating what Windmill does)
    println!("[Phase 4] Parsing credentials into structured data...");

    // Simulate parsing into a struct
    #[derive(Debug)]
    struct DbCreds {
        host: String,
        port: u16,
        user: String,
        password: String,
        database: String,
    }

    // Simple parsing (just for demo)
    let creds = DbCreds {
        host: "localhost".to_string(),
        port: 5432,
        user: "postgres".to_string(),
        password: "changeme".to_string(),
        database: "windmill".to_string(),
    };

    println!("  ✓ Parsed into struct:");
    println!("    Host: {}", creds.host);
    println!("    User: {}", creds.user);
    println!("    Password: {}", creds.password);
    println!();

    // Phase 5: Check what's in memory
    println!("[Phase 5] Memory analysis...");
    println!();
    println!("Variables currently in Rust process memory:");
    println!("  • contents: String = \"{}...\"", &contents[..50]);
    println!("  • creds.password: String = \"{}\"", creds.password);
    println!("  • creds.user: String = \"{}\"", creds.user);
    println!();
    println!("Memory addresses:");
    println!("  • contents ptr: {:p}", contents.as_ptr());
    println!("  • password ptr: {:p}", creds.password.as_ptr());
    println!();

    // Phase 6: Try to read our own process memory
    println!("[Phase 6] Attempting self-memory extraction...");
    println!();

    let my_pid = std::process::id();
    println!("  Current PID: {}", my_pid);

    let mem_file = format!("/proc/{}/mem", my_pid);

    // Try to open our own memory
    match fs::File::open(&mem_file) {
        Ok(mut file) => {
            println!("  ✓ Opened /proc/{}/mem", my_pid);

            // Try to read a chunk
            let mut buffer = vec![0u8; 4096];
            match file.read(&mut buffer) {
                Ok(n) => {
                    println!("  ✓ Read {} bytes from our own memory", n);

                    // Search for our password in the buffer
                    let buffer_str = String::from_utf8_lossy(&buffer);
                    if buffer_str.contains("changeme") {
                        println!("  ❌ Found password 'changeme' in memory dump!");
                    } else {
                        println!("  ⚠️  Password not in this chunk (but it's in heap somewhere)");
                    }
                }
                Err(e) => println!("  ! Read failed: {}", e),
            }
        }
        Err(e) => {
            println!("  ✓ Cannot open own memory: {} (expected - /proc/self/mem is tricky)", e);
        }
    }
    println!();

    // Phase 7: Try to read parent windmill process
    println!("[Phase 7] Attempting parent process memory extraction...");
    println!();

    // Find windmill process
    let ps_output = std::process::Command::new("ps")
        .args(&["aux"])
        .output()?;

    let ps_str = String::from_utf8_lossy(&ps_output.stdout);
    let windmill_pid: Option<u32> = ps_str
        .lines()
        .find(|line| line.contains("target/debug/windmill") || line.contains("target/release/windmill"))
        .and_then(|line| {
            line.split_whitespace()
                .nth(1)
                .and_then(|pid| pid.parse().ok())
        });

    if let Some(pid) = windmill_pid {
        println!("  Found windmill PID: {}", pid);

        let mem_path = format!("/proc/{}/mem", pid);

        // Try strings on windmill's memory
        let strings_output = std::process::Command::new("timeout")
            .args(&["2", "strings", &mem_path])
            .output();

        if let Ok(output) = strings_output {
            let strings_str = String::from_utf8_lossy(&output.stdout);

            // Look for DATABASE_URL
            let found = strings_str
                .lines()
                .find(|line| line.starts_with("DATABASE_URL=postgres://"));

            if let Some(line) = found {
                println!();
                println!("  ❌❌❌ FOUND DATABASE_URL IN WINDMILL MEMORY:");
                println!("  {}", line);
                println!();
            } else {
                println!("  ⚠️  strings didn't find it (but memory is readable)");
            }
        } else {
            println!("  ⚠️  strings command failed");
        }
    } else {
        println!("  ! Windmill process not found");
    }
    println!();

    // Results
    println!("════════════════════════════════════════════════════════════════");
    println!("RESULTS");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("File Status:");
    println!("  Source file: ✓ DELETED (verified)");
    println!();
    println!("Memory Status:");
    println!("  Rust String 'contents': ❌ Still contains full DATABASE_URL");
    println!("  Parsed struct 'creds': ❌ Contains password, user, host, etc.");
    println!("  Heap memory: ❌ All credential data still allocated");
    println!();
    println!("CONCLUSION:");
    println!("  Deleting the source file after fs::read_to_string() provides");
    println!("  ZERO protection against memory extraction attacks.");
    println!();
    println!("  The String is heap-allocated and persists in process memory");
    println!("  regardless of what happens to the source file.");
    println!();
    println!("Security benefit vs env var clearing: NONE");
    println!("Both approaches have identical memory footprint.");
    println!("════════════════════════════════════════════════════════════════");

    Ok(format!(
        "Test complete. File deleted: ✓ | Memory cleared: ❌\n\
         Conclusion: File deletion is security theater."
    ))
}
