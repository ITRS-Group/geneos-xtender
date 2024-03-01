#!/usr/bin/env bats
export ASSERTION_SOURCE="/tests/bats/assertions"
load "/tests/bats/assertion-test-helpers"

setup() {
    BATS_TMP=$(mktemp -d -t bats-XXXXXXXXXX)
}

teardown() {
    rm -rf "$BATS_TMP"
}

header_line="name,status,shortOutput,label,value,uom,warn,crit,min,max,command,performanceDataString,longOutput,executionTime,variablesFound,variablesNotFound"

assert_first_line_is_header() {
    assert_line_matches 0 "$header_line"
}

assert_template_is_found() {
    assert_output_matches "<!>templatesFound,.*$1.*"
}

# Pre tests

@test "[pre-test] verify that xtender is at /usr/bin/xtender" {
    [ -f /usr/bin/xtender ]
}

# @test "[pre-test] verify that the templates folder is not empty" {
#     [ -d /opt/itrs/xtender/templates ]
#     [ $(ls -l /opt/itrs/xtender/templates/*.yaml | wc -l) -gt 1 ]
# }

# @test "[pre-test] verify that the plugins folder is not empty" {
#     [ -d /opt/itrs/xtender/plugins ]
#     [ $(ls -l /opt/itrs/xtender/plugins/* | wc -l) -gt 0 ]
# }

# Begin main tests

@test "invoking xtender with the invalid option --foo" {
    run /usr/bin/xtender --foo
    assert_status 2
    assert_output_matches "error: unexpected argument '--foo' found"
}

@test "invoking xtender with the valid option --help" {
    run /usr/bin/xtender --help
    assert_status 0
    assert_output_matches "Geneos Xtender:"
    assert_output_matches "Usage:"
    assert_output_matches "Arguments:"
    assert_output_matches "Options:"
}

@test "invoking xtender with the valid option -h" {
    run /usr/bin/xtender -h
    assert_status 0
    assert_output_matches "Geneos Xtender:"
    assert_output_matches "Usage:"
    assert_output_matches "Arguments:"
    assert_output_matches "Options:"
}

@test "invoking xtender with the valid option --version" {
    run /usr/bin/xtender --version
    assert_status 0
    assert_output_matches "^geneos-xtender [0-9]+\.[0-9]+\.[0-9]+-?(alpha|beta|rc)?[0-9]*$"
}

@test "invoking xtender with the valid option -V" {
    run /usr/bin/xtender -V
    assert_status 0
    assert_output_matches "^geneos-xtender [0-9]+\.[0-9]+\.[0-9]+-?(alpha|beta|rc)?[0-9]*$"
}

network_base_json=$(cat <<EOF
{
   "attribute" : [],
   "hosttemplate" : [
      {
         "description" : "Basic network checks",
         "has_icon" : "0",
         "managementurls" : [],
         "name" : "Network - Base",
         "servicechecks" : [
            {
               "exception" : null,
               "name" : "Connectivity - LAN",
               "timed_exception" : null
            }
         ]
      }
   ],
   "servicecheck" : [
      {
         "alert_from_failure" : "1",
         "args" : "-H $HOSTADDRESS$ -w 100.0,20% -c 500.0,60%",
         "attribute" : null,
         "calculate_rate" : "no",
         "cascaded_from" : null,
         "check_attempts" : "3",
         "check_freshness" : "1",
         "check_interval" : "300",
         "checktype" : {
            "name" : "Active Plugin"
         },
         "critical_comparison" : null,
         "critical_value" : null,
         "dependencies" : [],
         "description" : "Checks that network interface is responding to ICMP echo requests",
         "event_handler" : "",
         "flap_detection_enabled" : "1",
         "invertresults" : "0",
         "label" : null,
         "level" : 0,
         "markdown_filter" : "0",
         "name" : "Connectivity - LAN",
         "notification_interval" : null,
         "notification_options" : "w,c,r",
         "oid" : null,
         "plugin" : {
            "name" : "check_icmp"
         },
         "retry_check_interval" : "60",
         "sensitive_arguments" : "1",
         "servicegroup" : {
            "name" : "Network - Base"
         },
         "snmptraprules" : [],
         "stale_state" : "3",
         "stale_text" : "UNKNOWN: Service results are stale",
         "stale_threshold_seconds" : "1800",
         "stalking" : null,
         "volatile" : "0",
         "warning_comparison" : null,
         "warning_value" : null
      }
   ],
   "servicegroup" : [
      {
         "name" : "Network - Base"
      }
   ]
}
EOF
)

network_base_template=$(cat <<EOF
# name: Network - Base
# description: Basic network checks
- name: Connectivity - LAN
  command: |
    check_icmp -H $HOSTADDRESS$ -w 100.0,20% -c 500.0,60%

EOF
)

@test "invoking xtender with the option -o on a valid Opspack config.json file" {
    echo "$network_base_json" > "$BATS_TMP"/network-base.json
    run /usr/bin/xtender -o "$BATS_TMP"/network-base.json
    assert_success
    assert_output "$network_base_template"
}

@test "invoking xtender with the option -k while using encrypted variables" {
    cat <<'EOF' > "$BATS_TMP"/secret.key
salt=89A6A795C9CCECB5
key=26D6EDD53A0AFA8FA1AA3FBCD2FFF2A0BF4809A4E04511F629FC732C2A42A8FC
iv =472A3557ADDD2525AD4E555738636A67

EOF

    cat <<'EOF' > "$BATS_TMP"/echo_encrypted.yaml
# name: Echo - Encrypted
# description: Echo two variables that are encrypted
- name: Echo Encrypted
  command: |
    echo encrypted_variables: A: $ENCRYPTED_VARIABLE_1$ B: $ENCRYPTED_VARIABLE_2$
EOF

    cat <<'EOF' > "$BATS_TMP"/echo_mixed_1.yaml
# name: Echo - Mixed 1
# description: Echo two variables, one encrypted and one unencrypted
- name: Echo Mixed 1
  command: |
    echo mixed_variables: A: $ENCRYPTED_VARIABLE_1$ B: $UNENCRYPTED_VARIABLE$
EOF

    cat <<'EOF' > "$BATS_TMP"/echo_mixed_2.yaml
# name: Echo - Mixed 2
# description: Echo two variables, one unencrypted and one encrypted
- name: Echo Mixed 2
  command: |
    echo mixed_variables: A: $UNENCRYPTED_VARIABLE$ B: $ENCRYPTED_VARIABLE_1$
EOF

    cat <<'EOF' > "$BATS_TMP"/echo_unencrypted.yaml
# name: Echo - Unencrypted
# description: Echo a variable that is unencrypted
- name: Echo Unencrypted
  command: |
    echo unencrypted_variable: $UNENCRYPTED_VARIABLE$
EOF

    export ENCRYPTED_VARIABLE_1="+encs+346BA94B6E0008C76A2B368E4D894CF6"
    export ENCRYPTED_VARIABLE_2="+encs+346BA94B6E0008C76A2B368E4D894CF6"
    export UNENCRYPTED_VARIABLE="this_is_unencrypted"

    run /usr/bin/xtender -k "$BATS_TMP"/secret.key -- "$BATS_TMP"/echo_encrypted.yaml "$BATS_TMP"/echo_unencrypted.yaml "$BATS_TMP"/echo_mixed_1.yaml "$BATS_TMP"/echo_mixed_2.yaml
    assert_success
    assert_output_matches "Echo Encrypted,0,encrypted_variables: A: 127.0.0.1 B: 127.0.0.1,,,,,,,,echo encrypted_variables: A: \*\*\* B: \*\*\*,,,[0-9]+\.[0-9]+ s,ENCRYPTED_VARIABLE_1=\*\*\*\\\\,ENCRYPTED_VARIABLE_2=\*\*\*,"
    assert_output_matches "Echo Unencrypted,0,unencrypted_variable: this_is_unencrypted,,,,,,,,echo unencrypted_variable: this_is_unencrypted,,,[0-9]+\.[0-9]+ s,UNENCRYPTED_VARIABLE=\"this_is_unencrypted\","
    assert_output_matches "Echo Mixed 1,0,mixed_variables: A: 127.0.0.1 B: this_is_unencrypted,,,,,,,,echo mixed_variables: A: \*\*\* B: this_is_unencrypted,,,[0-9]+\.[0-9]+ s,ENCRYPTED_VARIABLE_1=\*\*\*\\\\,UNENCRYPTED_VARIABLE=\"this_is_unencrypted\","
    assert_output_matches "Echo Mixed 2,0,mixed_variables: A: this_is_unencrypted B: 127.0.0.1,,,,,,,,echo mixed_variables: A: this_is_unencrypted B: \*\*\*,,,[0-9]+\.[0-9]+ s,ENCRYPTED_VARIABLE_1=\*\*\*\\\\,UNENCRYPTED_VARIABLE=\"this_is_unencrypted\","
}
