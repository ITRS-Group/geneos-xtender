use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*;
use pretty_assertions::assert_eq;
use serde::__private::from_utf8_lossy; // Used for writing assertions
use std::fs::File;
use std::io::Write;
use std::process::Command; // Run programs
use std::time::Instant;
use tempfile::tempdir;

const CSV_HEADER_COLUMNS: &str = "name,status,shortOutput,label,value,uom,warn,crit,min,max,command,performanceDataString,longOutput,executionTime,variablesFound,variablesNotFound";
const ENCRYPTED_VAR_EXAMPLE1: &str = r"+encs+BCC9E963342C9CFEFB45093F3437A680";
const ENCRYPTED_VAR_EXAMPLE2: &str = r"+encs+3510EEEF4163EB21C671FB5C57ADFCE2";
const PLAINTEXT_VAR_EXAMPLE: &str = r"Hello world!";
const SAMPLE_OPSPACK_JSON: &str = r#"{
  "hosttemplate": [
    {
      "name": "Check HTTP",
      "description": "Check HTTP",
      "plugin": {
        "name": "check_http"
      }
    }
  ],
  "servicecheck": [
    {
      "name": "Check HTTP",
      "args": "-H $HOSTADDRESS:1$ -u %URL:1%",
      "plugin": {
        "name": "check_http"
      }
    }
  ]
}"#;
const SAMPLE_OPSPACK_AS_TEMPLATE: &str = r#"# name: Check HTTP
# description: Check HTTP
- name: Check HTTP
  command: |
    check_http -H $HOSTADDRESS_1$ -u $URL_1$
"#;
const SAMPLE_PLUGIN_EXITS_WITH_2: &str = r#"#!/bin/bash
set -e
echo "CRITICAL: This plugin exits with code 2"
exit 2
"#;
const SAMPLE_YAML_DASH_ARG: &str = r#"
---
- name: hello
  command: |
    echo hello,0,Hello world!,
...
"#;
const SAMPLE_YAML_ENCRYPTED_VAR: &str = r#"
---
- name: test_encrypted_variable
  command: |
    stat $ENCRYPTED_TEST_VAR$
...
"#;
const SAMPLE_YAML_EXITS_WITH_2: &str = r#"
---
- name: test_with_yaml_file
  command: |
    bash $SCRIPT$
...
"#;
const SAMPLE_YAML_HELLO_COMMA: &str = r#"
---
- name: test_hello_world_with_comma
  command: |
    echo Hello, world!
...
"#;
const SAMPLE_YAML_INCORRECT_FORMAT: &str = r#"
---
checks:
  - name: test_with_yaml_file
    command: echo
    args:
      - Hello
      - world!
...
"#;
const SAMPLE_YAML_INVALID_CMD: &str = r#"
---
- name: Invalid command
  command: |
    /bin/foo_bar
...
"#;
const SAMPLE_YAML_KNOWN_ENV_VARS: &str = r#"
---
- name: test_user_variable
  command: |
    echo "user: $USER$"
- name: test_path_variable
  command: |
    echo "path: $PATH$"
...
"#;
const SAMPLE_YAML_MIXED_VARS: &str = r#"
---
- name: test_encrypted_variable1 $ENCRYPTED_TEST_VAR_1$
  command: |
    echo "encrypted: $ENCRYPTED_TEST_VAR_1$"
- name: test_encrypted_variable2 $ENCRYPTED_TEST_VAR_2$
  command: |
    ls -al $ENCRYPTED_TEST_VAR_2$ | head -n 1
- name: test_unencrypted_variable1 $UNENCRYPTED_TEST_VAR_1$
  command: |
    echo "unencrypted: $UNENCRYPTED_TEST_VAR_1$"
...
"#;
const SAMPLE_YAML_MULTI_ENV_VARS: &str = r#"
---
- name: test_user_and_path_variable
  command: |
    echo "user: $USER$, path: $PATH$"
...
"#;
const SAMPLE_YAML_MULTIPLE_CHECKS: &str = r#"
---
- name: test_with_multiple_yaml_file_1
  command: |
    echo Hello world!
- name: test_with_multiple_yaml_file_2
  command: |
    echo Hello world!
...
"#;
const SAMPLE_YAML_ONE_SEC_TIMEOUT: &str = r#"
---
- name: timeout
  timeout: 1
  command: |
    sleep 2
...
"#;
const SAMPLE_YAML_RANGE_VAR: &str = r#"
---
- name: test_!!A:1..3!!
  command: |
    printf '%s %s' Hello !!A:1..3!!
...
"#;
const SAMPLE_YAML_SHORT_SLEEP_CMD: &str = r#"
---
- name: test_1
  command: |
    sleep 1
- name: test_2
  command: |
    sleep 1
...
"#;
const SAMPLE_YAML_SINGLE_CHECK: &str = r#"
---
- name: test_with_single_yaml_file
  command: |
    echo hello
...
"#;
const SAMPLE_YAML_SINGLE_QUOTED: &str = r#"
---
- name: test_with_single_quoted_string
  command: |
    printf '%s %s' Hello world!
...
"#;
const SAMPLE_YAML_TWO_DIFF_RANGES: &str = r#"
---
- name: test_!!A:1..2!!_!!B:2..3!!
  command: |
    printf '%s %s %s' Hello !!A:1..2!! !!B:2..3!!
...
"#;
const SAMPLE_YAML_TWO_SAME_RANGES: &str = r#"
---
- name: test_!!A:1..3!!_!!B:1..3!!
  command: |
    printf '%s %s %s' Hello !!A:1..3!! !!B:1..3!!
...
"#;
const SAMPLE_YAML_UNKNOWN_ENV_VARS: &str = r#"
---
- name: test_foo_bar_baz_variable
  command: |
    echo "foo_bar_baz: $FOO_BAR_BAZ$"
...
"#;
const SAMPLE_YAML_VALID_SHASUM_CMD: &str = r#"
---
- name: Valid command
  command: |
    sha256sum "Hello World"
...
"#;
const VALID_KEY_FILE_CONTENTS: &str = r#"salt=89A6A795C9CCECB5
key=26D6EDD53A0AFA8FA1AA3FBCD2FFF2A0BF4809A4E04511F629FC732C2A42A8FC
iv =472A3557ADDD2525AD4E555738636A67
"#;

#[test]
fn test_cli_display_help() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage:"))
        .stdout(predicate::str::contains("Options:"));

    Ok(())
}

#[test]
fn test_cli_display_version() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--version");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_command_1_sec_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("xtender")?;

    let expected_output = "timeout,3,UNKNOWN: Timed out after 1 second";

    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;

    writeln!(file_1, "{}", SAMPLE_YAML_ONE_SEC_TIMEOUT)?;

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

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_command_exited_with_2() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;

    let file_2_path = dir.path().join("file_2.sh");
    let mut file_2 = File::create(&file_2_path)?;

    writeln!(file_1, "{}", SAMPLE_YAML_EXITS_WITH_2)?;
    writeln!(file_2, "{}", SAMPLE_PLUGIN_EXITS_WITH_2)?;

    std::env::set_var("SCRIPT", file_2_path);

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        // The check should return CRITICAL with a status of 2 in the status column, but the CLI app
        // itself should not fail.
        .success()
        .stdout(predicate::str::contains(
            "test_with_yaml_file,2,CRITICAL: This plugin",
        ));

    drop(file_1);
    drop(file_2);
    dir.close()?;

    std::env::remove_var("SCRIPT");

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_command_two_diff_range_vars_and_quotes() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();
    writeln!(file_1, "{}", SAMPLE_YAML_TWO_DIFF_RANGES).unwrap();

    let expected_output_1 = "test_1_2,0,Hello 1 2,,,,,,,,printf \'%s %s %s\' Hello 1 2,,";
    let expected_output_2 = "test_1_3,0,Hello 1 3,,,,,,,,printf \'%s %s %s\' Hello 1 3,,";
    let expected_output_3 = "test_2_2,0,Hello 2 2,,,,,,,,printf \'%s %s %s\' Hello 2 2,,";
    let expected_output_4 = "test_2_3,0,Hello 2 3,,,,,,,,printf \'%s %s %s\' Hello 2 3,,";

    let mut cmd = Command::cargo_bin("xtender").unwrap();

    cmd.arg("-d").arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains(expected_output_1))
        .stdout(predicate::str::contains(expected_output_2))
        .stdout(predicate::str::contains(expected_output_3))
        .stdout(predicate::str::contains(expected_output_4));

    drop(file_1);
    dir.close().unwrap();
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_command_two_range_vars_and_quotes() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", SAMPLE_YAML_TWO_SAME_RANGES)?;

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
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
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

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_command_with_range_variable() -> Result<(), Box<dyn std::error::Error>> {
    let expected_output_1 = "test_1,0,Hello 1,,,,,,,,printf \'%s %s\' Hello 1,,";
    let expected_output_2 = "test_2,0,Hello 2,,,,,,,,printf \'%s %s\' Hello 2,,";
    let expected_output_3 = "test_3,0,Hello 3,,,,,,,,printf \'%s %s\' Hello 3,,";

    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", SAMPLE_YAML_RANGE_VAR)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains(expected_output_1))
        .stdout(predicate::str::contains(expected_output_2))
        .stdout(predicate::str::contains(expected_output_3));

    drop(file_1);
    dir.close()?;

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_display_correct_execution_time() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();
    writeln!(file_1, "{}", SAMPLE_YAML_SHORT_SLEEP_CMD).unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("--").arg(&file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("executionTime"))
        .stdout(predicate::str::contains("test_1,0,,,,,,,,,sleep 1,,,1.0"));

    drop(file_1);
    dir.close().unwrap();
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_display_multi_known_env_vars() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();

    writeln!(file_1, "{}", SAMPLE_YAML_KNOWN_ENV_VARS).unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("--").arg(&file_1_path);

    let current_user = match std::env::var("USER") {
        Ok(val) => val,
        Err(_) => {
            std::env::set_var("USER", "unknown");
            "unknown".to_string()
        }
    };

    let current_path = match std::env::var("PATH") {
        Ok(val) => val,
        Err(_) => {
            std::env::set_var("PATH", "unknown");
            "unknown".to_string()
        }
    };

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains(format!(
            "\"user: {}\",",
            current_user
        )))
        .stdout(predicate::str::contains(format!(
            "\"path: {}\",",
            current_path
        )))
        .stdout(predicate::str::contains(format!(
            ",USER=\"{}\",\n",
            current_user
        )))
        .stdout(predicate::str::contains(format!(
            ",PATH=\"{}\",\n",
            current_path
        )));

    drop(file_1);
    dir.close().unwrap();
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_display_multi_known_env_vars_single_command() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();

    writeln!(file_1, "{}", SAMPLE_YAML_MULTI_ENV_VARS).unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("--").arg(&file_1_path);

    let current_user = match std::env::var("USER") {
        Ok(val) => val,
        Err(_) => {
            std::env::set_var("USER", "unknown");
            "unknown".to_string()
        }
    };

    let current_path = match std::env::var("PATH") {
        Ok(val) => val,
        Err(_) => {
            std::env::set_var("PATH", "unknown");
            "unknown".to_string()
        }
    };

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains("user:"))
        .stdout(predicate::str::contains("path:"))
        .stdout(predicate::str::contains(format!(
            "\"user: {}\\, path: {}\",",
            current_user, current_path
        )))
        // Even though the variables in the command were listed with "USER" first, the output should
        // be sorted alphabetically.
        .stdout(predicate::str::contains(format!(
            ",PATH=\"{}\"\\,USER=\"{}\",\n",
            current_path, current_user
        )));

    drop(file_1);
    dir.close().unwrap();
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_display_unknown_env_vars() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();

    writeln!(file_1, "{}", SAMPLE_YAML_UNKNOWN_ENV_VARS).unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("--").arg(&file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains("foo_bar_baz:"))
        .stdout(predicate::str::contains(",,FOO_BAR_BAZ\n"));

    drop(file_1);
    dir.close().unwrap();
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_error_encrypted_var_without_key() {
    std::env::set_var("ENCRYPTED_TEST_VAR_1", ENCRYPTED_VAR_EXAMPLE1);

    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();

    writeln!(file_1, "{}", SAMPLE_YAML_MIXED_VARS).unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("--").arg(&file_1_path);

    cmd.assert().failure().stderr(predicate::str::contains(
        "ERROR - Unable to build check: The variable \"ENCRYPTED_TEST_VAR_1\" is encrypted but no KeyFile was provided",
    ));

    drop(file_1);
    dir.close().unwrap();

    std::env::remove_var("ENCRYPTED_TEST_VAR_1");
}

#[test]
fn test_error_on_incorrect_yaml() -> Result<(), Box<dyn std::error::Error>> {
    let expected_output = "Make sure that each entry in the template follows this format:";

    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", SAMPLE_YAML_INCORRECT_FORMAT)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(expected_output));

    drop(file_1);
    dir.close()?;

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_invalid_command_execution_success() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let yaml_file_path = dir.path().join("invalid_command.yaml");
    let mut file = File::create(&yaml_file_path)?;

    writeln!(file, "{}", SAMPLE_YAML_INVALID_CMD)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(yaml_file_path);

    // The command should fail, but the CLI app itself should not fail.
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains(",/bin/foo_bar,"));

    drop(file);
    dir.close()?;

    Ok(())
}

#[test]
fn test_output_missing_template_headline() -> Result<(), Box<dyn std::error::Error>> {
    let expected_output = r#"<!>templatesFound,
<!>templatesNotFound,/path/to/non_existing.yaml"#;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg("/path/to/non_existing.yaml");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains(expected_output));

    Ok(())
}

#[test]
fn test_output_multiple_missing_templates() -> Result<(), Box<dyn std::error::Error>> {
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

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_output_not_containing_secret_var() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("ENCRYPTED_VAR_EXAMPLE1", ENCRYPTED_VAR_EXAMPLE1);

    let dir = tempdir()?;
    let key_file_path = dir.path().join("keyfile");
    let mut key_file = File::create(&key_file_path).unwrap();

    writeln!(key_file, "{}", VALID_KEY_FILE_CONTENTS).unwrap();

    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();

    writeln!(file_1, "{}", SAMPLE_YAML_ENCRYPTED_VAR).unwrap();

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("-d")
        .arg("-k")
        .arg(key_file_path)
        .arg("--")
        .arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("12345").not());

    drop(file_1);
    dir.close()?;

    std::env::remove_var("ENCRYPTED_VAR_EXAMPLE1");

    Ok(())
}

#[test]
fn test_output_template_from_opspack_json() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.json");
    let mut file_1 = File::create(&file_1_path)?;

    writeln!(file_1, "{}", SAMPLE_OPSPACK_JSON)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("-o").arg(file_1_path);

    let binding = cmd.assert().success();
    let output_string = from_utf8_lossy(&binding.get_output().stdout);

    assert_eq!(SAMPLE_OPSPACK_AS_TEMPLATE, output_string);

    drop(file_1);
    dir.close()?;

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_output_with_comma_inclusion() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;

    writeln!(file_1, "{}", SAMPLE_YAML_HELLO_COMMA)?;

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

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_parallel_faster_than_sequential() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();
    writeln!(file_1, "{}", SAMPLE_YAML_SHORT_SLEEP_CMD).unwrap();

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
fn test_sequential_option_equivalence() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();
    writeln!(file_1, "{}", SAMPLE_YAML_TWO_DIFF_RANGES).unwrap();

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

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_success_command_single_quotes() -> Result<(), Box<dyn std::error::Error>> {
    let expected_output_1 =
        "test_with_single_quoted_string,0,Hello world!,,,,,,,,printf \'%s %s\' Hello world!,,";

    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", SAMPLE_YAML_SINGLE_QUOTED)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains(expected_output_1));

    drop(file_1);
    dir.close()?;
    Ok(())
}

#[test]
fn test_success_multiple_entry_yaml() -> Result<(), Box<dyn std::error::Error>> {
    let expected_output_1 = "test_with_multiple_yaml_file_1,0,Hello world!";
    let expected_output_2 = "test_with_multiple_yaml_file_2,0,Hello world!";

    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", SAMPLE_YAML_MULTIPLE_CHECKS)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains(expected_output_1))
        .stdout(predicate::str::contains(expected_output_2));

    drop(file_1);
    dir.close()?;

    Ok(())
}

#[test]
fn test_success_multiple_file_options() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;

    let file_1_path = dir.path().join("file_1.yaml");
    let file_2_path = dir.path().join("file_2.yaml");

    let mut file_1 = File::create(&file_1_path)?;
    let mut file_2 = File::create(&file_2_path)?;

    writeln!(file_1, "{}", SAMPLE_YAML_SINGLE_CHECK)?;
    writeln!(file_2, "{}", SAMPLE_YAML_MULTIPLE_CHECKS)?;

    let expected_output_1 = "test_with_single_yaml_file,0,hello";
    let expected_output_2 = "test_with_multiple_yaml_file_1,0,Hello world!";
    let expected_output_3 = "test_with_multiple_yaml_file_2,0,Hello world!";

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("--").arg(file_1_path).arg(file_2_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains(expected_output_1))
        .stdout(predicate::str::contains(expected_output_2))
        .stdout(predicate::str::contains(expected_output_3));

    drop(file_1);
    drop(file_2);
    dir.close()?;

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_shasum_command_success() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let yaml_file_path = dir.path().join("valid_command.yaml");
    let mut file = File::create(&yaml_file_path)?;
    writeln!(file, "{}", SAMPLE_YAML_VALID_SHASUM_CMD)?;

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("-d").arg("--").arg(yaml_file_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS));

    drop(file);
    dir.close()?;

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_success_encrypted_var_with_key() {
    std::env::set_var("ENCRYPTED_TEST_VAR_1", ENCRYPTED_VAR_EXAMPLE1);
    std::env::set_var("ENCRYPTED_TEST_VAR_2", ENCRYPTED_VAR_EXAMPLE2);
    std::env::set_var("UNENCRYPTED_TEST_VAR_1", PLAINTEXT_VAR_EXAMPLE);

    let dir = tempdir().unwrap();
    let key_file_path = dir.path().join("keyfile");
    let mut key_file = File::create(&key_file_path).unwrap();

    writeln!(key_file, "{}", VALID_KEY_FILE_CONTENTS).unwrap();

    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();

    writeln!(file_1, "{}", SAMPLE_YAML_MIXED_VARS).unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("-k").arg(key_file_path).arg("--").arg(&file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains("test_encrypted_variable1 ***"))
        // The output of the secret command should still be displayed. If you echo the decrypted
        // variable, it should be displayed. We don't make an effort to obfuscate the output of
        // your command.
        .stdout(predicate::str::contains(",encrypted: 12345,"))
        // But we don't want to show the secret variable in the command since this would then
        // always reveal the secret variable.
        .stdout(predicate::str::contains(",echo \"encrypted: ***\","))
        .stdout(predicate::str::contains(",ENCRYPTED_TEST_VAR_1=***,\n"))
        .stdout(predicate::str::contains("test_encrypted_variable2 ***"))
        // The output of the secret command should still be displayed. If you echo the decrypted
        // variable, it should be displayed. We don't make an effort to obfuscate the output of
        // your command.
        .stdout(predicate::str::contains("total "))
        // But we don't want to show the secret variable in the command since this would then
        // always reveal the secret variable.
        .stdout(predicate::str::contains(",ls -al *** |"))
        .stdout(predicate::str::contains(",ENCRYPTED_TEST_VAR_2=***,\n"))
        .stdout(predicate::str::contains(
            "test_unencrypted_variable1 Hello world!",
        ))
        .stdout(predicate::str::contains(",unencrypted: Hello world!,"))
        .stdout(predicate::str::contains(
            ",echo \"unencrypted: Hello world!\",",
        ))
        .stdout(predicate::str::contains(
            ",UNENCRYPTED_TEST_VAR_1=\"Hello world!\",\n",
        ));

    drop(file_1);
    dir.close().unwrap();

    std::env::remove_var("ENCRYPTED_TEST_VAR_1");
    std::env::remove_var("ENCRYPTED_TEST_VAR_2");
    std::env::remove_var("UNENCRYPTED_TEST_VAR_1");
}

#[test]
fn test_success_single_entry_yaml() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", SAMPLE_YAML_SINGLE_CHECK)?;

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

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_yaml_args_dash_not_breaking_parsing() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", SAMPLE_YAML_DASH_ARG)?;

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
