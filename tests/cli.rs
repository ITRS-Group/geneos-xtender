use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*;
use pretty_assertions::assert_eq;
use serial_test::serial;
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
const SAMPLE_YAML_UNKNOWN_AND_KNOWN_ENV_VARS: &str = r#"
---
- name: test_mixed_variables
  command: |
    echo "should_be_empty: $SHOULD_BE_EMPTY$, should_be_known: $SHOULD_BE_KNOWN$"
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
#[serial]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_command_exited_with_2() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;

    let file_2_path = dir.path().join("file_2.sh");
    let mut file_2 = File::create(&file_2_path)?;

    writeln!(file_1, "{}", SAMPLE_YAML_EXITS_WITH_2)?;
    writeln!(file_2, "{}", SAMPLE_PLUGIN_EXITS_WITH_2)?;

    unsafe {
        std::env::set_var("SCRIPT", file_2_path);
    }

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

    unsafe {
        std::env::remove_var("SCRIPT");
    }

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
fn test_command_from_template_with_range_variable() -> Result<(), Box<dyn std::error::Error>> {
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
fn test_command_from_option_with_range_variable_and_timeout(
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_output_1 = "templatesFound,\n";
    let expected_output_2 = "templatesNotFound,\n";
    let expected_output_3 = "test_1,0,Hello 1,,,,,,,,printf \'%s %s\' Hello 1,,";
    let expected_output_4 = "test_2,0,Hello 2,,,,,,,,printf \'%s %s\' Hello 2,,";
    let expected_output_5 = "test_3,0,Hello 3,,,,,,,,printf \'%s %s\' Hello 3,,";

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("-c")
        .arg("printf '%s %s' Hello !!A:1..3!!")
        .arg("-n")
        .arg("test_!!A:1..3!!")
        .arg("-t")
        .arg("10");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains(expected_output_1))
        .stdout(predicate::str::contains(expected_output_2))
        .stdout(predicate::str::contains(expected_output_3))
        .stdout(predicate::str::contains(expected_output_4))
        .stdout(predicate::str::contains(expected_output_5));

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
#[serial]
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
            unsafe {
                std::env::set_var("USER", "unknown");
            }
            "unknown".to_string()
        }
    };

    let current_path = match std::env::var("PATH") {
        Ok(val) => val,
        Err(_) => {
            unsafe {
                std::env::set_var("PATH", "unknown");
            }
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
#[serial]
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
            unsafe {
                std::env::set_var("USER", "unknown");
            }
            "unknown".to_string()
        }
    };

    let current_path = match std::env::var("PATH") {
        Ok(val) => val,
        Err(_) => {
            unsafe {
                std::env::set_var("PATH", "unknown");
            }
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
#[serial]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_display_mixed_env_vars_when_allow_empty_vars() {
    unsafe {
        std::env::set_var("SHOULD_BE_KNOWN", "foo");
    }
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();

    writeln!(file_1, "{}", SAMPLE_YAML_UNKNOWN_AND_KNOWN_ENV_VARS).unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("--allow-empty-vars");
    cmd.arg("--").arg(&file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains(
            "should_be_empty: \\, should_be_known: foo",
        ))
        .stdout(predicate::str::contains(
            ",SHOULD_BE_EMPTY=\"\"\\,SHOULD_BE_KNOWN=\"foo\",\n",
        ));

    drop(file_1);
    dir.close().unwrap();
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_ignore_unknown_env_vars_when_allow_empty_vars() {
    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();

    writeln!(file_1, "{}", SAMPLE_YAML_UNKNOWN_ENV_VARS).unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("--allow-empty-vars");
    cmd.arg("--").arg(&file_1_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(CSV_HEADER_COLUMNS))
        .stdout(predicate::str::contains("foo_bar_baz:"))
        .stdout(predicate::str::contains(",FOO_BAR_BAZ=\"\",\n"));

    drop(file_1);
    dir.close().unwrap();
}

#[test]
#[serial]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_error_encrypted_var_without_key() {
    unsafe {
        std::env::set_var("ENCRYPTED_TEST_VAR_1", ENCRYPTED_VAR_EXAMPLE1);
    }

    let dir = tempdir().unwrap();
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path).unwrap();

    writeln!(file_1, "{}", SAMPLE_YAML_MIXED_VARS).unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("--").arg(&file_1_path);

    cmd.assert()
       .failure()
       .stderr(predicate::str::contains(
        "Unable to build check: The variable \"ENCRYPTED_TEST_VAR_1\" is encrypted but no KeyFile was provided",
    ));

    drop(file_1);
    dir.close().unwrap();

    unsafe {
        std::env::remove_var("ENCRYPTED_TEST_VAR_1");
    }
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
#[serial]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_output_not_containing_secret_var() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        std::env::set_var("ENCRYPTED_VAR_EXAMPLE1", ENCRYPTED_VAR_EXAMPLE1);
    }

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

    unsafe {
        std::env::remove_var("ENCRYPTED_VAR_EXAMPLE1");
    }

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
    let output_string = String::from_utf8_lossy(&binding.get_output().stdout);

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
#[serial]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_success_encrypted_var_with_key() {
    unsafe {
        std::env::set_var("ENCRYPTED_TEST_VAR_1", ENCRYPTED_VAR_EXAMPLE1);
        std::env::set_var("ENCRYPTED_TEST_VAR_2", ENCRYPTED_VAR_EXAMPLE2);
        std::env::set_var("UNENCRYPTED_TEST_VAR_1", PLAINTEXT_VAR_EXAMPLE);
    }

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

    unsafe {
        std::env::remove_var("ENCRYPTED_TEST_VAR_1");
        std::env::remove_var("ENCRYPTED_TEST_VAR_2");
        std::env::remove_var("UNENCRYPTED_TEST_VAR_1");
    }
}

#[test]
fn test_success_single_command_as_option() -> Result<(), Box<dyn std::error::Error>> {
    let expected_output_0 = "name,status,shortOutput";
    let expected_output_1 = "<!>templatesFound,\n";
    let expected_output_2 = "<!>templatesNotFound,\n";
    let expected_output_3 = "test_with_single_command_as_option,0,hello";

    let mut cmd = Command::cargo_bin("xtender")?;

    cmd.arg("-c")
        .arg("echo hello")
        .arg("-n")
        .arg("test_with_single_command_as_option");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected_output_0))
        .stdout(predicate::str::contains(expected_output_1))
        .stdout(predicate::str::contains(expected_output_2))
        .stdout(predicate::str::contains(expected_output_3));

    Ok(())
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

/// When templates include both valid and invalid paths, the tool should still run the valid
/// ones and report the missing ones in the templatesNotFound line.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_mixed_found_and_not_found_templates() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("valid.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", SAMPLE_YAML_SINGLE_CHECK)?;

    let mut cmd = Command::cargo_bin("xtender")?;
    cmd.arg("--")
        .arg(&file_1_path)
        .arg("/nonexistent/missing.yaml");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "test_with_single_yaml_file,0,hello",
        ))
        .stdout(predicate::str::contains(format!(
            "<!>templatesFound,{}",
            file_1_path.to_str().unwrap()
        )))
        .stdout(predicate::str::contains(
            "<!>templatesNotFound,/nonexistent/missing.yaml",
        ));

    drop(file_1);
    dir.close()?;
    Ok(())
}

/// Single command mode should not require templates.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_single_command_with_timeout_option() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("xtender")?;
    cmd.arg("-c")
        .arg("echo hello world")
        .arg("-n")
        .arg("hello_test")
        .arg("-t")
        .arg("10");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("hello_test,0,hello world"));

    Ok(())
}

/// Sequential flag should produce the same results as parallel for a single check.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_sequential_single_check() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", SAMPLE_YAML_SINGLE_CHECK)?;

    let mut cmd = Command::cargo_bin("xtender")?;
    cmd.arg("--sequential").arg("--").arg(file_1_path);

    cmd.assert().success().stdout(predicate::str::contains(
        "test_with_single_yaml_file,0,hello",
    ));

    drop(file_1);
    dir.close()?;
    Ok(())
}

/// Debug mode should output debug info to stderr.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_debug_mode_writes_to_stderr() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_1_path = dir.path().join("file_1.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", SAMPLE_YAML_SINGLE_CHECK)?;

    let mut cmd = Command::cargo_bin("xtender")?;
    cmd.arg("-d").arg("--").arg(file_1_path);

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("DEBUG"));

    drop(file_1);
    dir.close()?;
    Ok(())
}

/// An invalid command in a template should not crash the CLI. The check should still appear
/// in the output with an appropriate status.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_invalid_command_among_valid_commands() -> Result<(), Box<dyn std::error::Error>> {
    let yaml = r#"
---
- name: valid_check
  command: |
    echo valid_output
- name: invalid_check
  command: |
    /nonexistent/binary
...
"#;

    let dir = tempdir()?;
    let file_1_path = dir.path().join("mixed.yaml");
    let mut file_1 = File::create(&file_1_path)?;
    writeln!(file_1, "{}", yaml)?;

    let mut cmd = Command::cargo_bin("xtender")?;
    cmd.arg("--").arg(file_1_path);

    // Both checks should appear: the invalid one with status 3 (UNKNOWN), the valid one with 0.
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("valid_check,0,valid_output"))
        .stdout(predicate::str::contains("invalid_check,3,"));

    drop(file_1);
    dir.close()?;
    Ok(())
}

/// Verify that multi-line plugin output is preserved in the CSV longOutput field.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_multiline_output_in_csv() -> Result<(), Box<dyn std::error::Error>> {
    let yaml = r#"
---
- name: multiline_check
  command: |
    printf 'First line\nSecond line\nThird line'
...
"#;

    let dir = tempdir()?;
    let file_path = dir.path().join("multiline.yaml");
    let mut file = File::create(&file_path)?;
    writeln!(file, "{}", yaml)?;

    let mut cmd = Command::cargo_bin("xtender")?;
    cmd.arg("--").arg(file_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("multiline_check,0,First line"))
        .stdout(predicate::str::contains("Second line\\nThird line"));

    drop(file);
    dir.close()?;
    Ok(())
}

/// Checks with perfdata in the output should have it extracted to the performanceDataString column.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_perfdata_extraction_in_cli() -> Result<(), Box<dyn std::error::Error>> {
    let yaml = r#"
---
- name: perf_check
  command: |
    echo 'OK - all good|metric=42%;80;90;0;100'
...
"#;

    let dir = tempdir()?;
    let file_path = dir.path().join("perfdata.yaml");
    let mut file = File::create(&file_path)?;
    writeln!(file, "{}", yaml)?;

    let mut cmd = Command::cargo_bin("xtender")?;
    cmd.arg("--").arg(file_path);

    cmd.assert().success().stdout(predicate::str::contains(
        "perf_check,0,OK - all good,metric,42.0,%,80,90,0,100",
    ));

    drop(file);
    dir.close()?;
    Ok(())
}

/// Verify the opspack conversion handles JSON with multiple servicechecks.
#[test]
fn test_opspack_conversion_multiple_servicechecks() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{
  "hosttemplate": [{"name": "Multi Checks", "description": "Multiple checks"}],
  "servicecheck": [
    {"name": "Check A", "args": "-H $HOST$", "plugin": {"name": "check_a"}},
    {"name": "Check B", "args": "-H $HOST$", "plugin": {"name": "check_b"}}
  ]
}"#;

    let dir = tempdir()?;
    let file_path = dir.path().join("multi.json");
    let mut file = File::create(&file_path)?;
    writeln!(file, "{}", json)?;

    let mut cmd = Command::cargo_bin("xtender")?;
    cmd.arg("-o").arg(file_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("# name: Multi Checks"))
        .stdout(predicate::str::contains("- name: Check A"))
        .stdout(predicate::str::contains("check_a -H $HOST$"))
        .stdout(predicate::str::contains("- name: Check B"))
        .stdout(predicate::str::contains("check_b -H $HOST$"));

    drop(file);
    dir.close()?;
    Ok(())
}

/// Verify that a check with a 0-second timeout fails immediately as UNKNOWN.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_zero_second_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let yaml = r#"
---
- name: zero_timeout
  timeout: 0
  command: |
    sleep 10
...
"#;

    let dir = tempdir()?;
    let file_path = dir.path().join("timeout.yaml");
    let mut file = File::create(&file_path)?;
    writeln!(file, "{}", yaml)?;

    let mut cmd = Command::cargo_bin("xtender")?;
    cmd.arg("--").arg(file_path);

    cmd.assert().success().stdout(predicate::str::contains(
        "zero_timeout,3,UNKNOWN: Timed out after 0 seconds",
    ));

    drop(file);
    dir.close()?;
    Ok(())
}

/// Verify that the --allow-empty-vars flag is reflected in variable output when vars are in the name.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_allow_empty_vars_in_check_name() -> Result<(), Box<dyn std::error::Error>> {
    let yaml = r#"
---
- name: check_$NONEXISTENT_VAR_12345$
  command: |
    echo hello
...
"#;

    let dir = tempdir()?;
    let file_path = dir.path().join("name_var.yaml");
    let mut file = File::create(&file_path)?;
    writeln!(file, "{}", yaml)?;

    let mut cmd = Command::cargo_bin("xtender")?;
    cmd.arg("--allow-empty-vars").arg("--").arg(file_path);

    // With allow-empty-vars, the missing variable should be replaced with empty string
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("check_,0,hello"));

    drop(file);
    dir.close()?;
    Ok(())
}

/// Anything that is not a bare template name is a path chosen by the operator and is
/// read as given, including paths through ".." and files without a YAML extension.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_template_paths_are_read_as_given() {
    let dir = tempdir().unwrap();
    std::fs::create_dir(dir.path().join("subdir")).unwrap();
    std::fs::write(
        dir.path().join("plain.txt"),
        "- name: plain\n  command: echo hello\n",
    )
    .unwrap();

    for path in [
        dir.path().join("subdir").join("..").join("plain.txt"),
        dir.path().join("plain.txt"),
    ] {
        let output = Command::cargo_bin("xtender")
            .unwrap()
            .arg("--")
            .arg(&path)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{}", path.display());
        assert!(stdout.contains("\nplain,0,hello,"), "{stdout}");
    }
}

/// A template that is neither a readable path nor a known name is reported as not found.
#[test]
fn test_missing_template_is_reported() {
    let output = Command::cargo_bin("xtender")
        .unwrap()
        .arg("--")
        .arg("no_such_template_xyz")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("<!>templatesNotFound,no_such_template_xyz"),
        "{stdout}"
    );
    assert!(stderr.contains("no_such_template_xyz"), "{stderr}");
}

/// When --allow-empty-vars is active and a variable is missing, stderr should contain
/// a warning about the substitution, without needing --debug.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_allow_empty_vars_emits_warning() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("warn_test.yaml");
    let mut file = File::create(&file_path).unwrap();
    writeln!(
        file,
        "---\n- name: warn_check\n  command: echo $DEFINITELY_MISSING_VAR_12345$"
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("xtender").unwrap();
    cmd.arg("--allow-empty-vars").arg("--").arg(&file_path);

    cmd.assert().success().stderr(predicate::str::contains(
        "Variable 'DEFINITELY_MISSING_VAR_12345' not found, substituting empty string",
    ));

    drop(file);
    dir.close().unwrap();
}

/// Run xtender on a template written to a temp file and return the process output.
fn run_template(template: &str) -> std::process::Output {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("template.yaml");
    std::fs::write(&file_path, template).unwrap();
    Command::cargo_bin("xtender")
        .unwrap()
        .arg("--")
        .arg(&file_path)
        .output()
        .unwrap()
}

/// A malformed template must abort the run without writing any CSV, so that a
/// partial dataview never reaches the Toolkit plugin.
#[test]
fn test_malformed_templates_fail_without_output() {
    let cases = [
        ("invalid syntax", "- name: a\n  command: [unclosed\n"),
        ("check is not a mapping", "- just a string\n"),
        ("missing name", "- command: echo hi\n"),
        ("missing command", "- name: a\n"),
        ("non-string name", "- name: [a, b]\n  command: echo hi\n"),
        (
            "negative timeout",
            "- name: a\n  command: echo hi\n  timeout: -1\n",
        ),
        (
            "text timeout",
            "- name: a\n  command: echo hi\n  timeout: soon\n",
        ),
        (
            "fractional timeout",
            "- name: a\n  command: echo hi\n  timeout: 1.5\n",
        ),
    ];

    for (case, template) in cases {
        let output = run_template(template);
        assert!(!output.status.success(), "{case}: expected failure");
        assert!(
            output.stdout.is_empty(),
            "{case}: expected no stdout, got {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

/// Template values are trimmed, quoted strings keep their colons, and an
/// explicit timeout overrides the default.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_template_values_are_parsed() {
    let template = "---\n- name: '  spaced  '\n  command: \"echo a:b\"\n  timeout: 0\n  extra: ignored\n- name: block\n  command: |\n    echo block\n";
    let output = run_template(template);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("\nspaced,3,UNKNOWN: Timed out after 0 seconds"),
        "{stdout}"
    );
    assert!(stdout.contains("\nblock,0,block,"), "{stdout}");
}
