#!/usr/bin/env bats
export ASSERTION_SOURCE="/tests/bats/assertions"
load "/tests/bats/assertion-test-helpers"

setup() {
    BATS_TMP=$(mktemp -d -t bats-XXXXXXXXXX)
}

teardown() {
    rm -rf "$BATS_TMP"
}

header_line="name,status,shortOutput,label,value,uom,warn,crit,min,max,command,performanceDataString,longOutput"

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
#     [ -d /opt/xtender/templates ]
#     [ $(ls -l /opt/xtender/templates/*.yaml | wc -l) -gt 1 ]
# }

# @test "[pre-test] verify that the plugins folder is not empty" {
#     [ -d /opt/xtender/plugins ]
#     [ $(ls -l /opt/xtender/plugins/* | wc -l) -gt 0 ]
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

# @test "invoking xtender with more than one template" {
#     export HOSTADDRESS="127.0.0.1"
#     export SNMP_COMMUNITY="public"
#     export TRAY="1"

#     run /usr/bin/xtender -- network-base snmp-printer
#     assert_success
#     assert_first_line_is_header
#     assert_template_is_found "network-base"
#     assert_template_is_found "snmp-printer"
# }

# @test "invoking xtender with all the templates one at a time" {
#     echo "# Will now test all the templates one at a time" >&3
#     for file in /opt/xtender/templates/*.yaml
#     do
#         if [[ -f "$file" ]]; then
#             template=$(basename -s .yaml "$file")
#             echo "##############################"
#             echo "# Now testing template $template"

#             # Set all the environment variables needed by one or more templates
#             export HOSTADDRESS="127.0.0.1"
#             export SNMP_COMMUNITY="public"
#             export TRAY="1"
#             export INTERFACE="eth0"
#             export DOMAIN="itrsgroup.com"
#             export EXPECTED_IP="127.0.0.1"
#             export INTERFACE_1=1
#             export INTERFACE_2=2
#             export INTERFACE_3=3
#             export INTERFACE_4=4
#             export SNMP_VERSION="2c"
#             export SNMP_PORT="161"
#             export SNMPV3_USERNAME="not-a-username"
#             export SNMPV3_AUTHPASSWORD="not-an-actual-password"
#             export SNMPV3_AUTHPROTOCOL="SHA"
#             export SNMPV3_PRIVPROTOCOL="AES"
#             export SNMPV3_PRIVPASSWORD="not-an-actual-password"
#             export SALESFORCE_LOGIN_1="not-a-username"
#             export SALESFORCE_LOGIN_2="not-a-password"
#             export SALESFORCE_AUTH_1="not-a-real-key"
#             export SALESFORCE_AUTH_2="not-a-real-secret"
#             export SALESFORCE_AUTH_3="not-a-real-token"
#             export DC_DOMAIN="itrs-group"
#             export DC_TOP_DOMAIN="com"

#             run /usr/bin/xtender -- "$template"
#             assert_success
#             assert_first_line_is_header
#             assert_template_is_found "$template"
#             echo "# Done testing template $template" >&3
#             echo "##############################"
#         fi
#     done
# }
