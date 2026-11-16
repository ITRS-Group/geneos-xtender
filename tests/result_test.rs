use geneos_xtender::result::*;
use pretty_assertions::assert_eq;

const COLUMNS: &str = "name,status,shortOutput,label,value,uom,warn,crit,min,max,command,performanceDataString,longOutput,executionTime,variablesFound,variablesNotFound";

/// When perfdata has an unparseable crit threshold, status should be 3 (UNKNOWN)
/// rather than falling through to 0 (OK) or panicking.
#[test]
fn test_unparseable_crit_threshold_returns_unknown() {
    let c = CheckResultBuilder::new()
        .name("Bad Crit")
        .command("check_foo")
        .parse_output("something|metric=50%;80;GARBAGE;0;100")
        .build();

    let csv_results = CheckResults(vec![c]).process().as_csv_string().unwrap();
    assert!(
        csv_results.contains("Bad Crit,3,"),
        "Expected status 3 (UNKNOWN) for unparseable crit threshold, got: {}",
        csv_results
    );
}

/// When perfdata has an unparseable warn threshold, status should be 3 (UNKNOWN).
#[test]
fn test_unparseable_warn_threshold_returns_unknown() {
    let c = CheckResultBuilder::new()
        .name("Bad Warn")
        .command("check_foo")
        .parse_output("something|metric=50%;GARBAGE;;0;100")
        .build();

    let csv_results = CheckResults(vec![c]).process().as_csv_string().unwrap();
    assert!(
        csv_results.contains("Bad Warn,3,"),
        "Expected status 3 (UNKNOWN) for unparseable warn threshold, got: {}",
        csv_results
    );
}

/// Perfdata with unbalanced quotes should not panic; it should degrade gracefully.
#[test]
fn test_unbalanced_quotes_in_perfdata_no_panic() {
    let c = CheckResultBuilder::new()
        .name("Bad Quotes")
        .command("check_foo")
        .parse_output("something|'broken=50%;80;90;0;100")
        .build();

    // Should not panic; we just want to verify it doesn't crash
    let _csv_results = CheckResults(vec![c]).process().as_csv_string().unwrap();
}

fn test_check_results_as_csv(check: CheckResult, expected_csv: Vec<&str>) {
    let csv_results = CheckResults(vec![check]).process().as_csv_string().unwrap();
    for (line, expected_line) in csv_results.lines().zip(expected_csv.iter()) {
        assert_eq!(line, *expected_line);
    }
}

#[test]
fn test_check_results_as_csv_short_output_with_comma() {
    let c = CheckResultBuilder::new()
        .name("Hello World with comma")
        .command("echo Hello, World")
        .status(0)
        .short_output("Hello, World")
        .performance_data("1")
        .build();

    let e = vec![
        COLUMNS,
        "Hello World with comma,0,Hello\\, World,,,,,,,,echo Hello\\, World,1,,,,",
    ];

    test_check_results_as_csv(c, e);
}

#[test]
fn test_check_results_as_csv_with_hardcoded_status() {
    let c = CheckResultBuilder::new()
        .name("Foo Bar")
        .command("echo foo bar")
        .status(2)
        .short_output("foo bar")
        .build();

    let e = vec![COLUMNS, "Foo Bar,2,foo bar,,,,,,,,echo foo bar,,,,,"];

    test_check_results_as_csv(c, e);
}

#[test]
fn test_check_results_as_csv_multi_line_ok_check_with_perfdata() {
    let c = CheckResultBuilder::new()
    .name("check_snmpif test output")
    .command("check_snmpif traffic -v 2c -c public -i 4 -H 192.168.1.1 --warn-in 70m --warn-out 20m --crit-in 90m --crit-out 35m -b 100m")
    .status(0)
    .parse_output("OK: Avg Traffic: 46.58kbps (0.05% / 100Mbps) in, 91.67kbps (0.09% / 100Mbps) out|in_traffic=0.05%;70.00;90.00;; out_traffic=0.09%;20.00;35.00;;")
    .build();

    let e = vec![
    COLUMNS,
    "check_snmpif test output,0,OK: Avg Traffic: 46.58kbps (0.05% / 100Mbps) in\\, 91.67kbps (0.09% / 100Mbps) out,,,,,,,,check_snmpif traffic -v 2c -c public -i 4 -H 192.168.1.1 --warn-in 70m --warn-out 20m --crit-in 90m --crit-out 35m -b 100m,in_traffic=0.05%;70.00;90.00;; out_traffic=0.09%;20.00;35.00;;,,,,",
    "\tcheck_snmpif test output#in_traffic,0,,in_traffic,0.05,%,70.00,90.00,,,,,,,,",
    "\tcheck_snmpif test output#out_traffic,0,,out_traffic,0.09,%,20.00,35.00,,,,,,,,",
];

    test_check_results_as_csv(c, e);
}

#[test]
fn test_check_results_as_csv_multi_line_ok_check_with_different_kinds_of_perfdata() {
    let c = CheckResultBuilder::new()
    .name("Connectivity 192.168.1.190")
    .command("/opt/opsview/monitoringscripts/plugins/check_icmp -H 192.168.1.190 -w 100.0,20% -c 500.0,60%")
    .status(0)
    .parse_output("OK - 192.168.1.190: rta 0.222ms, lost 0%|rta=0.222ms;100.000;500.000;0; pl=0%;20;60;; rtmax=0.380ms;;;; rtmin=0.169ms;;;;")
    .build();
    let e = vec![
    COLUMNS,
    "Connectivity 192.168.1.190,0,OK - 192.168.1.190: rta 0.222ms\\, lost 0%,,,,,,,,/opt/opsview/monitoringscripts/plugins/check_icmp -H 192.168.1.190 -w 100.0\\,20% -c 500.0\\,60%,rta=0.222ms;100.000;500.000;0; pl=0%;20;60;; rtmax=0.380ms;;;; rtmin=0.169ms;;;;,,,,",
    "\tConnectivity 192.168.1.190#rta,0,,rta,0.222,ms,100.000,500.000,0,,,,,,,",
    "\tConnectivity 192.168.1.190#pl,0,,pl,0.0,%,20,60,,,,,,,,",
    "\tConnectivity 192.168.1.190#rtmax,0,,rtmax,0.38,ms,,,,,,,,,,",
    "\tConnectivity 192.168.1.190#rtmin,0,,rtmin,0.169,ms,,,,,,,,,,",
];

    test_check_results_as_csv(c, e);
}

#[test]
fn test_check_results_as_csv_warning_check_with_single_perfdata() {
    let c = CheckResultBuilder::new()
        .name("SNMP CPU Usage 192.168.1.3")
        .command("/opt/opsview/monitoringscripts/plugins/check_snmp_loadavg -w 0 -c 1 -H 192.168.1.3 -C public -v 2c -p 161")
        .parse_output("Status is WARNING - Load 0.01 (1 Min avg)|'Load Average'=0.01")
        .status(1)
        .build();

    let e = vec![
    COLUMNS,
    "SNMP CPU Usage 192.168.1.3,1,Status is WARNING - Load 0.01 (1 Min avg),Load Average,0.01,,,,,,/opt/opsview/monitoringscripts/plugins/check_snmp_loadavg -w 0 -c 1 -H 192.168.1.3 -C public -v 2c -p 161,'Load Average'=0.01,,,,"
];

    test_check_results_as_csv(c, e);
}

#[test]
fn test_check_results_as_csv_warning_check_with_multiple_perfdata() {
    let c = CheckResultBuilder::new()
        .name("Interface 4 Traffic")
        .command("/opt/opsview/monitoringscripts/plugins/check_snmpif traffic -v 2c -c public -i 4 -H 192.168.1.1 --warn-in 1m --warn-out 20m --crit-in 2m --crit-out 35m -b 100m")
        .parse_output("WARNING: Avg Traffic: 1.38Mbps (1.38% / 100Mbps) in, 445.17kbps (0.45% / 100Mbps) out|in_traffic=1.38%;1.00;2.00;; 'out traffic'=0.45%;20.00;35.00;;") // purposfully using a space in the perfdata label
        .status(1)
        .build();

    let e = vec![
        COLUMNS,
        "Interface 4 Traffic,1,WARNING: Avg Traffic: 1.38Mbps (1.38% / 100Mbps) in\\, 445.17kbps (0.45% / 100Mbps) out,,,,,,,,/opt/opsview/monitoringscripts/plugins/check_snmpif traffic -v 2c -c public -i 4 -H 192.168.1.1 --warn-in 1m --warn-out 20m --crit-in 2m --crit-out 35m -b 100m,in_traffic=1.38%;1.00;2.00;; 'out traffic'=0.45%;20.00;35.00;;,,,,",
        "\tInterface 4 Traffic#in_traffic,1,,in_traffic,1.38,%,1.00,2.00,,,,,,,,",
        "\tInterface 4 Traffic#out traffic,0,,out traffic,0.45,%,20.00,35.00,,,,,,,,",
    ];

    test_check_results_as_csv(c, e);
}

/// When a check has no explicit status and single perfdata with a critical threshold that is
/// breached, status_from_perfdata should infer status 2 (CRITICAL).
#[test]
fn test_status_inferred_critical_from_perfdata() {
    let c = CheckResultBuilder::new()
        .name("Disk Usage")
        .command("check_disk")
        .parse_output("Disk usage high|usage=95%;80;90;0;100")
        .build();

    let csv_results = CheckResults(vec![c]).process().as_csv_string().unwrap();
    // The single perfdata metric: value=95, warn=80, crit=90 → 95 > 90 → status should be 2
    assert!(
        csv_results.contains("Disk Usage,2,"),
        "Expected status 2 (CRITICAL) when value exceeds crit threshold, got: {}",
        csv_results
    );
}

/// When a check has no explicit status and single perfdata with a warning threshold that is
/// breached (but not critical), status_from_perfdata should infer status 1 (WARNING).
#[test]
fn test_status_inferred_warning_from_perfdata() {
    let c = CheckResultBuilder::new()
        .name("Disk Usage")
        .command("check_disk")
        .parse_output("Disk usage medium|usage=85%;80;90;0;100")
        .build();

    let csv_results = CheckResults(vec![c]).process().as_csv_string().unwrap();
    // value=85, warn=80, crit=90 → 85 > 80 but < 90 → status should be 1
    assert!(
        csv_results.contains("Disk Usage,1,"),
        "Expected status 1 (WARNING) when value exceeds warn but not crit, got: {}",
        csv_results
    );
}

/// When a check has no explicit status and single perfdata within all thresholds,
/// status_from_perfdata should infer status 0 (OK).
#[test]
fn test_status_inferred_ok_from_perfdata() {
    let c = CheckResultBuilder::new()
        .name("Disk Usage")
        .command("check_disk")
        .parse_output("Disk usage OK|usage=50%;80;90;0;100")
        .build();

    let csv_results = CheckResults(vec![c]).process().as_csv_string().unwrap();
    // value=50, warn=80, crit=90 → 50 < 80 → status should be 0
    assert!(
        csv_results.contains("Disk Usage,0,"),
        "Expected status 0 (OK) when value is within thresholds, got: {}",
        csv_results
    );
}

/// When perfdata has a value but no warn/crit thresholds, status should default to 0 (OK).
#[test]
fn test_status_inferred_ok_when_no_thresholds() {
    let c = CheckResultBuilder::new()
        .name("Uptime")
        .command("check_uptime")
        .parse_output("Up for 42 days|uptime=42d")
        .build();

    let csv_results = CheckResults(vec![c]).process().as_csv_string().unwrap();
    assert!(
        csv_results.contains("Uptime,0,"),
        "Expected status 0 when no thresholds defined, got: {}",
        csv_results
    );
}

/// When the check has an explicit status set, status_from_perfdata should not override it.
/// The explicit status should be preserved in the main row.
#[test]
fn test_explicit_status_not_overridden_by_perfdata() {
    let c = CheckResultBuilder::new()
        .name("Service Check")
        .command("check_service")
        .status(0)
        .parse_output("Service OK|connections=95%;80;90;;")
        .build();

    let csv_results = CheckResults(vec![c]).process().as_csv_string().unwrap();
    // Explicit status 0 should persist even though perfdata would infer CRITICAL
    assert!(
        csv_results.contains("Service Check,0,"),
        "Explicit status should not be overridden by perfdata inference, got: {}",
        csv_results
    );
}

/// When no perfdata is present and no explicit status, the check should still produce valid CSV.
#[test]
fn test_check_result_with_no_perfdata() {
    let c = CheckResultBuilder::new()
        .name("Simple Check")
        .command("echo hello")
        .status(0)
        .short_output("hello")
        .build();

    let csv_results = CheckResults(vec![c]).process().as_csv_string().unwrap();
    assert!(csv_results.contains(COLUMNS));
    assert!(csv_results.contains("Simple Check,0,hello"));
}

/// Empty CheckResults should still produce CSV with headers.
#[test]
fn test_empty_check_results_produce_headers() {
    let csv_results = CheckResults(vec![]).process().as_csv_string().unwrap();
    assert!(
        csv_results.contains(COLUMNS),
        "Empty results should still contain CSV headers"
    );
}

/// Perfdata with all fields: value, UOM, warn, crit, min, max.
#[test]
fn test_check_results_perfdata_with_all_fields() {
    let c = CheckResultBuilder::new()
        .name("Full Perfdata")
        .command("check_full")
        .status(0)
        .parse_output("OK|metric=42%;80;90;0;100")
        .build();

    let csv_results = CheckResults(vec![c]).process().as_csv_string().unwrap();
    assert!(
        csv_results.contains("Full Perfdata,0,OK,metric,42.0,%,80,90,0,100"),
        "All perfdata fields should be extracted, got: {}",
        csv_results
    );
}

/// Long output (multi-line) should be preserved in the CSV.
#[test]
fn test_check_result_with_long_output() {
    let c = CheckResultBuilder::new()
        .name("Multi-line Check")
        .command("check_multi")
        .status(0)
        .parse_output("First line\nSecond line\nThird line")
        .build();

    let csv_results = CheckResults(vec![c]).process().as_csv_string().unwrap();
    assert!(
        csv_results.contains("Multi-line Check,0,First line,"),
        "Short output should be first line"
    );
    assert!(
        csv_results.contains("Second line\\nThird line"),
        "Long output should contain remaining lines with escaped newlines, got: {}",
        csv_results
    );
}

/// When perfdata and long output are both present (pipe on first line, then additional lines),
/// the current simplified parser treats everything after '|' as perfdata. Additional lines after
/// the first become part of the perfdata string and get split by shellwords. This documents the
/// current behavior so refactoring doesn't break it.
#[test]
fn test_check_result_with_perfdata_and_long_output() {
    let c = CheckResultBuilder::new()
        .name("Perfdata with long output")
        .command("check_verbose")
        .status(0)
        .parse_output("OK - summary|metric=5;10;20;;\nDetail line 1\nDetail line 2")
        .build();

    let csv_results = CheckResults(vec![c]).process().as_csv_string().unwrap();
    // Short output is extracted correctly from before the pipe
    assert!(
        csv_results.contains("Perfdata with long output,0,OK - summary,"),
        "Short output should stop at pipe, got: {}",
        csv_results
    );
    // The perfdata string includes everything after | (including the newlines)
    assert!(
        csv_results.contains("metric=5;10;20;;"),
        "Perfdata should be extracted from after pipe, got: {}",
        csv_results
    );
}
