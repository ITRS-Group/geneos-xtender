use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*; // Used for writing assertions
use std::fs::File;
use std::io::Write;
use std::process::Command; // Run programs
use std::time::Instant;
use tempfile::tempdir;

const COLUMNS: &str = "name,status,shortOutput,label,value,uom,warn,crit,min,max,command,performanceDataString,longOutput,executionTime,variablesFound,variablesNotFound";

#[test]
fn test_cli_help() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage:"))
        .stdout(predicate::str::contains("Options:"));

    Ok(())
}

#[test]
fn test_cli_version() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--version");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));

    Ok(())
}
#[test]
fn test_missing_template_in_headline() -> Result<(), Box<dyn std::error::Error>> {
    let expected_output = r#"<!>templatesFound,
<!>templatesNotFound,/path/to/non_existing.yaml"#;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg("/path/to/non_existing.yaml");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(COLUMNS))
        .stdout(predicate::str::contains(expected_output));

    Ok(())
}

const VALID_SHASUM_COMMAND_YAML: &str = r#"
- name: Valid command
  command: |
    sha256sum "Hello World"
"#;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_valid_shasum_command() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let yaml_file_path = dir.path().join("valid_command.yaml");
    let mut file = File::create(&yaml_file_path)?;
    writeln!(file, "{}", VALID_SHASUM_COMMAND_YAML)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("-d").arg("--").arg(yaml_file_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(COLUMNS));

    drop(file);
    dir.close()?;

    Ok(())
}

const INVALID_COMMAND_YAML: &str = r#"
- name: Invalid command
  command: |
    /bin/foo_bar
"#;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_invalid_command_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let yaml_file_path = dir.path().join("invalid_command.yaml");
    let mut file = File::create(&yaml_file_path)?;
    writeln!(file, "{}", INVALID_COMMAND_YAML)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(yaml_file_path);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Failed to execute command: \'/bin/foo_bar\' with error: \'No such file or directory (os error 2)\'",
    ));

    Ok(())
}

#[test]
fn test_missing_template_in_headline_with_multiple_missing_templates(
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_output = r#"name,status,shortOutput,label,value,uom,warn,crit,min,max,command,performanceDataString,longOutput,executionTime,variablesFound,variablesNotFound
<!>templatesFound,
<!>templatesNotFound,/path/to/non_existing.yaml, /path/to/non_existing_2.yaml"#;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--")
        .arg("/path/to/non_existing.yaml")
        .arg("/path/to/non_existing_2.yaml");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected_output));

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const TEST_DASH_ARG_YAML: &str = r#"
---
- name: hello
  command: |
    echo hello,0,Hello world!,
...
"#;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_that_passing_dash_in_yaml_args_is_not_breaking_string_parsing(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", TEST_DASH_ARG_YAML)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    let expected_output = "hello\\,0\\,Hello world!\\,";

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected_output));

    drop(file_1);
    dir.close()?;

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const ONE_SECOND_TIMEOUT_YAML: &str = r#"
---
- name: timeout
  timeout: 1
  command: |
    sleep 2
...
"#;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_1_second_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("xtender")?;

    let expected_output = "timeout,3,UNKNOWN: Timed out after 1 second";

    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;

    writeln!(file_1, "{}", ONE_SECOND_TIMEOUT_YAML)?;

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        // The check should return UNKNOWN with a status of 3 in the status column, but the CLI app
        // itself should not fail.
        .success()
        .stdout(predicate::str::contains(expected_output));

    drop(file_1);
    dir.close()?;

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const HELLO_WORLD_WITH_COMMA_YAML: &str = r#"
---
- name: test_hello_world_with_comma
  command: |
    echo Hello, world!
...
"#;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_hello_world_with_comma() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;

    writeln!(file_1, "{}", HELLO_WORLD_WITH_COMMA_YAML)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    let expected_output = "test_hello_world_with_comma,0,Hello\\, world!";

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected_output));

    drop(file_1);
    dir.close()?;

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const HELLO_WORLD_WITH_SPACE_YAML: &str = r#"
---
- name: test_hello_world_with_space
  command: |
    echo Hello world!
...
"#;

#[test]
fn test_hello_world_with_space() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;

    writeln!(file_1, "{}", HELLO_WORLD_WITH_SPACE_YAML)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    let expected_output = "test_hello_world_with_space,0,Hello world!";

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected_output));

    drop(file_1);
    dir.close()?;

    Ok(())
}

const BASIC_WRONG_YAML: &str = r#"
---
checks:
  - name: test_with_yaml_file
    command: echo
    args:
      - Hello
      - world!
...
"#;

#[test]
fn test_with_incorrect_yaml_file() -> Result<(), Box<dyn std::error::Error>> {
    let expected_output = "Make sure that each entry in the template follows this format:";

    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", BASIC_WRONG_YAML)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(expected_output));

    drop(file_1);
    dir.close()?;

    Ok(())
}

const BASIC_SINGLE_CHECK_YAML: &str = r#"
---
- name: test_with_single_yaml_file
  command: |
    echo hello
...
"#;

#[test]
fn test_with_correct_single_entry_yaml_file() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", BASIC_SINGLE_CHECK_YAML)?;

    let expected_output_0 = "name,status,shortOutput";
    let expected_output_1 = format!("<!>templatesFound,{}", file_1_path.to_str().unwrap());
    let expected_output_2 = "test_with_single_yaml_file,0,hello";

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected_output_0))
        .stdout(predicate::str::contains(expected_output_1))
        .stdout(predicate::str::contains(expected_output_2));

    drop(file_1);
    dir.close()?;

    Ok(())
}

const BASIC_MULTIPLE_CHECKS_YAML: &str = r#"
---
- name: test_with_multiple_yaml_file_1
  command: |
    echo Hello world!
- name: test_with_multiple_yaml_file_2
  command: |
    echo Hello world!
...
"#;

#[test]
fn test_with_correct_multiple_entry_yaml_file() -> Result<(), Box<dyn std::error::Error>> {
    let expected_output_1 = "test_with_multiple_yaml_file_1,0,Hello world!";
    let expected_output_2 = "test_with_multiple_yaml_file_2,0,Hello world!";

    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", BASIC_MULTIPLE_CHECKS_YAML)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(COLUMNS))
        .stdout(predicate::str::contains(expected_output_1))
        .stdout(predicate::str::contains(expected_output_2));

    drop(file_1);
    dir.close()?;

    Ok(())
}

#[test]
fn test_with_multiple_file_options_specified() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;

    let file_1_path = dir.path().join("file_1.yaml");
    let file_2_path = dir.path().join("file_2.yaml");

    let mut file_1 = File::create(&file_1_path)?;
    let mut file_2 = File::create(&file_2_path)?;

    writeln!(file_1, "{}", BASIC_SINGLE_CHECK_YAML)?;
    writeln!(file_2, "{}", BASIC_MULTIPLE_CHECKS_YAML)?;

    let expected_output_1 = "test_with_single_yaml_file,0,hello";
    let expected_output_2 = "test_with_multiple_yaml_file_1,0,Hello world!";
    let expected_output_3 = "test_with_multiple_yaml_file_2,0,Hello world!";

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(file_1_path).arg(file_2_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(COLUMNS))
        .stdout(predicate::str::contains(expected_output_1))
        .stdout(predicate::str::contains(expected_output_2))
        .stdout(predicate::str::contains(expected_output_3));

    drop(file_1);
    drop(file_2);
    dir.close()?;

    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn validate_command_functionality() {
    let mut cmd = std::process::Command::new("echo");

    cmd.arg("-e").arg("Hello world!");

    let output = cmd.output().expect("failed to execute process");

    println!("status: {}", output.status);
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"Hello world!\n");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const BASIC_CORRECT_YAML_WITH_SINGLE_QUOTED_STRING: &str = r#"
---
- name: test_with_single_quoted_string
  command: |
    printf '%s %s' Hello world!
...
"#;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_args_containing_single_quoted_string() -> Result<(), Box<dyn std::error::Error>> {
    let expected_output_1 =
        "test_with_single_quoted_string,0,Hello world!,,,,,,,,printf \'%s %s\' Hello world!,,";

    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", BASIC_CORRECT_YAML_WITH_SINGLE_QUOTED_STRING)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(COLUMNS))
        .stdout(predicate::str::contains(expected_output_1));

    drop(file_1);
    dir.close()?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const YAML_WITH_A_SINGLE_COMMAND_THAT_HAS_A_RANGE_VARIABLE: &str = r#"
---
- name: test_!!A:1..3!!
  command: |
    printf '%s %s' Hello !!A:1..3!!
...
"#;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_with_a_single_command_that_has_a_range_variable() -> Result<(), Box<dyn std::error::Error>>
{
    let expected_output_1 = "test_1,0,Hello 1,,,,,,,,printf \'%s %s\' Hello 1,,";
    let expected_output_2 = "test_2,0,Hello 2,,,,,,,,printf \'%s %s\' Hello 2,,";
    let expected_output_3 = "test_3,0,Hello 3,,,,,,,,printf \'%s %s\' Hello 3,,";

    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(
        file_1,
        "{}",
        YAML_WITH_A_SINGLE_COMMAND_THAT_HAS_A_RANGE_VARIABLE
    )?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(COLUMNS))
        .stdout(predicate::str::contains(expected_output_1))
        .stdout(predicate::str::contains(expected_output_2))
        .stdout(predicate::str::contains(expected_output_3));

    drop(file_1);
    dir.close()?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const YAML_WITH_A_SINGLE_COMMAND_THAT_HAS_TWO_IDENTICAL_RANGE_VARIABLES_AND_A_SINGLE_QUOTED_STRING: &str = r#"
---
- name: test_!!A:1..3!!_!!B:1..3!!
  command: |
    printf '%s %s %s' Hello !!A:1..3!! !!B:1..3!!
...
"#;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_with_a_single_command_that_has_two_range_variables_and_a_single_quoted_string(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(
        file_1,
        "{}",
        YAML_WITH_A_SINGLE_COMMAND_THAT_HAS_TWO_IDENTICAL_RANGE_VARIABLES_AND_A_SINGLE_QUOTED_STRING
    )?;

    let expected_output_1 = "test_1_1,0,Hello 1 1,,,,,,,,printf \'%s %s %s\' Hello 1 1,,";
    let expected_output_2 = "test_2_1,0,Hello 2 1,,,,,,,,printf \'%s %s %s\' Hello 2 1,,";
    let expected_output_3 = "test_3_1,0,Hello 3 1,,,,,,,,printf \'%s %s %s\' Hello 3 1,,";
    let expected_output_4 = "test_1_2,0,Hello 1 2,,,,,,,,printf \'%s %s %s\' Hello 1 2,,";
    let expected_output_5 = "test_2_2,0,Hello 2 2,,,,,,,,printf \'%s %s %s\' Hello 2 2,,";
    let expected_output_6 = "test_3_2,0,Hello 3 2,,,,,,,,printf \'%s %s %s\' Hello 3 2,,";
    let expected_output_7 = "test_1_3,0,Hello 1 3,,,,,,,,printf \'%s %s %s\' Hello 1 3,,";
    let expected_output_8 = "test_2_3,0,Hello 2 3,,,,,,,,printf \'%s %s %s\' Hello 2 3,,";
    let expected_output_9 = "test_3_3,0,Hello 3 3,,,,,,,,printf \'%s %s %s\' Hello 3 3,,";

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("-d").arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(COLUMNS))
        .stdout(predicate::str::contains(expected_output_1))
        .stdout(predicate::str::contains(expected_output_2))
        .stdout(predicate::str::contains(expected_output_3))
        .stdout(predicate::str::contains(expected_output_4))
        .stdout(predicate::str::contains(expected_output_5))
        .stdout(predicate::str::contains(expected_output_6))
        .stdout(predicate::str::contains(expected_output_7))
        .stdout(predicate::str::contains(expected_output_8))
        .stdout(predicate::str::contains(expected_output_9));

    drop(file_1);
    dir.close()?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const YAML_WITH_A_SINGLE_COMMAND_THAT_HAS_TWO_DIFFERENT_RANGE_VARIABLES_AND_A_SINGLE_QUOTED_STRING: &str = r#"
- name: test_!!A:1..2!!_!!B:2..3!!
  command: |
    printf '%s %s %s' Hello !!A:1..2!! !!B:2..3!!
"#;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_with_a_single_command_that_has_two_different_range_variables_and_a_single_quoted_string() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();
    writeln!(
        file_1,
        "{}",
        YAML_WITH_A_SINGLE_COMMAND_THAT_HAS_TWO_DIFFERENT_RANGE_VARIABLES_AND_A_SINGLE_QUOTED_STRING
    )
    .unwrap();

    let expected_output_1 = "test_1_2,0,Hello 1 2,,,,,,,,printf \'%s %s %s\' Hello 1 2,,";
    let expected_output_2 = "test_1_3,0,Hello 1 3,,,,,,,,printf \'%s %s %s\' Hello 1 3,,";
    let expected_output_3 = "test_2_2,0,Hello 2 2,,,,,,,,printf \'%s %s %s\' Hello 2 2,,";
    let expected_output_4 = "test_2_3,0,Hello 2 3,,,,,,,,printf \'%s %s %s\' Hello 2 3,,";

    let mut cmd = Command::cargo_bin("xtender").unwrap();

    cmd.arg("-d").arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(COLUMNS))
        .stdout(predicate::str::contains(expected_output_1))
        .stdout(predicate::str::contains(expected_output_2))
        .stdout(predicate::str::contains(expected_output_3))
        .stdout(predicate::str::contains(expected_output_4));

    drop(file_1);
    dir.close().unwrap();
}

#[test]
fn test_that_sequential_option_renders_the_same_result_as_without() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();
    writeln!(
        file_1,
        "{}",
        YAML_WITH_A_SINGLE_COMMAND_THAT_HAS_TWO_DIFFERENT_RANGE_VARIABLES_AND_A_SINGLE_QUOTED_STRING
    )
    .unwrap();

    let mut parallel_cmd = Command::cargo_bin("xtender").unwrap();
    parallel_cmd.arg("-d").arg("--").arg(&file_1_path);
    let parallel_output = parallel_cmd.output().unwrap();

    let mut sequential_cmd = Command::cargo_bin("xtender").unwrap();
    sequential_cmd
        .arg("-d")
        .arg("--sequential")
        .arg("--")
        .arg(file_1_path);
    let sequential_output = sequential_cmd.output().unwrap();

    // Smooth out the difference in execution time so that the test doesn't fail due to the
    // minor difference in execution time.

    let execution_time_re = regex::Regex::new(r"\d+.\d+ s,,\n").unwrap();

    let parallel_output_string = execution_time_re
        .replace_all(
            String::from_utf8_lossy(&parallel_output.stdout).as_ref(),
            "1.0 s,,\n",
        )
        .to_string();

    let sequential_output_string = execution_time_re
        .replace_all(
            String::from_utf8_lossy(&sequential_output.stdout).as_ref(),
            "1.0 s,,\n",
        )
        .to_string();

    assert_eq!(parallel_output.status, sequential_output.status);
    assert_eq!(parallel_output_string, sequential_output_string);

    drop(file_1);
    dir.close().unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const YAML_WITH_A_SHORT_SLEEP_COMMAND: &str = r#"
- name: test_1
  command: |
    sleep 1
- name: test_2
  command: |
    sleep 1
"#;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_that_parallel_option_is_faster_than_sequential() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();
    writeln!(file_1, "{}", YAML_WITH_A_SHORT_SLEEP_COMMAND).unwrap();

    let mut parallel_cmd = Command::cargo_bin("xtender").unwrap();
    parallel_cmd.arg("--").arg(&file_1_path);
    let parallel_start_time = Instant::now();
    let parallel_output = parallel_cmd.output().unwrap();
    let parallel_duration = parallel_start_time.elapsed();

    println!("parallel_output: {:?}", parallel_output);

    let sequential_start_time = Instant::now();
    let mut sequential_cmd = Command::cargo_bin("xtender").unwrap();
    sequential_cmd
        .arg("--sequential")
        .arg("--")
        .arg(file_1_path);
    let sequential_output = sequential_cmd.output().unwrap();
    let sequential_duration = sequential_start_time.elapsed();

    println!("sequential_output: {:?}", sequential_output);

    println!("parallel_duration: {:?}", parallel_duration);
    println!("sequential_duration: {:?}", sequential_duration);

    assert!(parallel_output.status.success());
    assert!(sequential_output.status.success());
    assert!(parallel_output.stderr.is_empty());
    assert!(sequential_output.stderr.is_empty());
    assert!(parallel_duration < sequential_duration);

    drop(file_1);
    dir.close().unwrap();
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_that_execution_time_is_correctly_printed() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();
    writeln!(file_1, "{}", YAML_WITH_A_SHORT_SLEEP_COMMAND).unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("--").arg(&file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("executionTime"))
        .stdout(predicate::str::contains("test_1,0,,,,,,,,,sleep 1,,,1.0"));

    drop(file_1);
    dir.close().unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const YAML_WITH_KNOWN_ENVIRONMENT_VARIABLES: &str = r#"
- name: test_user_variable
  command: |
    echo "user: $USER$"
- name: test_path_variable
  command: |
    echo "path: $PATH$"
"#;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_known_environment_variables_are_correctly_printed() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();

    writeln!(file_1, "{}", YAML_WITH_KNOWN_ENVIRONMENT_VARIABLES).unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("--").arg(&file_1_path);

    let current_user = std::env::var("USER").unwrap();
    let current_path = std::env::var("PATH").unwrap();

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(COLUMNS))
        .stdout(predicate::str::contains("user:"))
        .stdout(predicate::str::contains("path:"))
        .stdout(predicate::str::contains(",USER,\n"))
        .stdout(predicate::str::contains(",PATH,\n"))
        .stdout(predicate::str::contains(current_user))
        .stdout(predicate::str::contains(current_path));

    drop(file_1);
    dir.close().unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const YAML_WITH_UNKNOWN_ENVIRONMENT_VARIABLES: &str = r#"
- name: test_foo_bar_baz_variable
  command: |
    echo "foo_bar_baz: $FOO_BAR_BAZ$"
"#;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_unknown_environment_variables_are_correctly_printed() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();

    writeln!(file_1, "{}", YAML_WITH_UNKNOWN_ENVIRONMENT_VARIABLES).unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("--").arg(&file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(COLUMNS))
        .stdout(predicate::str::contains("foo_bar_baz:"))
        .stdout(predicate::str::contains(",,FOO_BAR_BAZ\n"));

    drop(file_1);
    dir.close().unwrap();
}
