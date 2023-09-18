use geneos_xtender::result::*;
use pretty_assertions::assert_eq;

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
        "name,status,shortOutput,label,value,uom,warn,crit,min,max,command,performanceDataString,longOutput,executionTime",
        "Hello World with comma,0,Hello\\, World,,,,,,,,echo Hello\\, World,1,,",
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

    let e = vec![
        "name,status,shortOutput,label,value,uom,warn,crit,min,max,command,performanceDataString,longOutput,executionTime",
        "Foo Bar,2,foo bar,,,,,,,,echo foo bar,,,",
    ];

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
    "name,status,shortOutput,label,value,uom,warn,crit,min,max,command,performanceDataString,longOutput,executionTime",
    "check_snmpif test output,0,OK: Avg Traffic: 46.58kbps (0.05% / 100Mbps) in\\, 91.67kbps (0.09% / 100Mbps) out,,,,,,,,check_snmpif traffic -v 2c -c public -i 4 -H 192.168.1.1 --warn-in 70m --warn-out 20m --crit-in 90m --crit-out 35m -b 100m,in_traffic=0.05%;70.00;90.00;; out_traffic=0.09%;20.00;35.00;;,,",
    "\tcheck_snmpif test output#in_traffic,0,,in_traffic,0.05,%,70.00,90.00,,,,,,",
    "\tcheck_snmpif test output#out_traffic,0,,out_traffic,0.09,%,20.00,35.00,,,,,,",
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
    "name,status,shortOutput,label,value,uom,warn,crit,min,max,command,performanceDataString,longOutput,executionTime",
    "Connectivity 192.168.1.190,0,OK - 192.168.1.190: rta 0.222ms\\, lost 0%,,,,,,,,/opt/opsview/monitoringscripts/plugins/check_icmp -H 192.168.1.190 -w 100.0\\,20% -c 500.0\\,60%,rta=0.222ms;100.000;500.000;0; pl=0%;20;60;; rtmax=0.380ms;;;; rtmin=0.169ms;;;;,,",
    "\tConnectivity 192.168.1.190#rta,0,,rta,0.222,ms,100.000,500.000,0,,,,,",
    "\tConnectivity 192.168.1.190#pl,0,,pl,0.0,%,20,60,,,,,,",
    "\tConnectivity 192.168.1.190#rtmax,0,,rtmax,0.38,ms,,,,,,,,",
    "\tConnectivity 192.168.1.190#rtmin,0,,rtmin,0.169,ms,,,,,,,,",
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
    "name,status,shortOutput,label,value,uom,warn,crit,min,max,command,performanceDataString,longOutput,executionTime",
    "SNMP CPU Usage 192.168.1.3,1,Status is WARNING - Load 0.01 (1 Min avg),Load Average,0.01,,,,,,/opt/opsview/monitoringscripts/plugins/check_snmp_loadavg -w 0 -c 1 -H 192.168.1.3 -C public -v 2c -p 161,'Load Average'=0.01,,"
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
        "name,status,shortOutput,label,value,uom,warn,crit,min,max,command,performanceDataString,longOutput,executionTime",
        "Interface 4 Traffic,1,WARNING: Avg Traffic: 1.38Mbps (1.38% / 100Mbps) in\\, 445.17kbps (0.45% / 100Mbps) out,,,,,,,,/opt/opsview/monitoringscripts/plugins/check_snmpif traffic -v 2c -c public -i 4 -H 192.168.1.1 --warn-in 1m --warn-out 20m --crit-in 2m --crit-out 35m -b 100m,in_traffic=1.38%;1.00;2.00;; 'out traffic'=0.45%;20.00;35.00;;,,",
        "\tInterface 4 Traffic#in_traffic,1,,in_traffic,1.38,%,1.00,2.00,,,,,,",
        "\tInterface 4 Traffic#out traffic,0,,out traffic,0.45,%,20.00,35.00,,,,,,",
    ];

    test_check_results_as_csv(c, e);
}
