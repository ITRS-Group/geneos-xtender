use geneos_xtender::check::*;
use pretty_assertions::{assert_eq, assert_ne};

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_run_check() {
    let p = Check::new("Hello World", "echo hello world", 2);
    let r = p.run();
    let (hello_world_exit_code, hello_world_output) = (r.status(), r.short_output());
    assert_eq!(hello_world_exit_code, Some(0));
    assert_eq!(hello_world_output, "hello world");
}

#[test]
#[should_panic]
fn test_run_invalid_command() {
    let p = Check::new("Invalid command", "/bin/foo_bar_baz", 2);
    let r = p.run();
    assert_eq!(r.status(), None);
}

#[tokio::test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn test_run_all() {
    let checks = vec![
        CheckBuilder::new()
            .name("Test check 1")
            .command("echo hello")
            .build(),
        CheckBuilder::new()
            .name("Test check 2")
            .command("echo world")
            .build(),
    ];

    let start_time = std::time::Instant::now();
    let results = run_all_checks_in_parallel(checks).await.unwrap();
    let elapsed_time = start_time.elapsed();

    assert_eq!(results.0.len(), 2);
    assert_eq!(results.0[0].short_output().trim(), "hello");
    assert_eq!(results.0[1].short_output().trim(), "world");
    println!("Elapsed time: {:?}", elapsed_time);
    assert!(elapsed_time < std::time::Duration::from_millis(50));
}

#[test]
#[should_panic]
fn test_invalid_variable_in_name() {
    CheckBuilder::new()
        .name("Hello $WORLD$")
        .command("echo hello world")
        .with_variables()
        .build();
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_valid_variable_in_name() {
    let p = CheckBuilder::new()
        .name("Hello $USER$")
        .command("echo hello world")
        .with_variables()
        .build();
    assert_ne!(p.name, "Hello VARIABLE_NOT_FOUND");
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_check_run_timed_out() {
    let check = Check::new("Test", "sleep 10", 0);
    let result = check.run();
    assert_eq!(result.status(), Some(3));
    assert_eq!(result.short_output(), "UNKNOWN: Timed out after 0 seconds");
}
