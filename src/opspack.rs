use serde_json;
use serde_yaml;

use crate::check::{CheckBuilder, Checks};

#[derive(Clone, Debug, Default, serde::Serialize, PartialEq)]
pub struct Opspack {
    pub name: String,
    pub description: String,
    #[serde(skip)]
    pub checks: Checks,
}

const OPSVIEW_VARIABLE_RE: &str = r"[$%]([A-Z_:0-9]+)[$%]";

fn harmonize_opspack_variables(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let variable_re = regex::Regex::new(OPSVIEW_VARIABLE_RE)?;
    let variables = variable_re
        .captures_iter(s)
        .map(|c| c.get(1).unwrap().as_str())
        .collect::<Vec<&str>>();

    if !variables.is_empty() {
        let mut s = s.to_string();

        for variable in variables {
            s = s
                .replace(
                    &format!("%{}%", variable),
                    &format!("${}$", variable.replace(':', "_")),
                )
                .replace(
                    &format!("${}$", variable),
                    &format!("${}$", variable.replace(':', "_")),
                );
        }

        return Ok(s);
    }

    Ok(s.to_string())
}

impl Opspack {
    pub fn new(name: &str, description: &str, checks: Checks) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            checks,
        }
    }

    pub fn from_json(json: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        let mut checks = Checks::new();

        let servicechecks = match v["servicecheck"].as_array() {
            Some(servicechecks) => servicechecks,
            None => return Err("No servicechecks found".into()),
        };

        for servicecheck in servicechecks {
            let name = servicecheck["name"].as_str().unwrap();
            let harmonized_name = harmonize_opspack_variables(name).unwrap();
            let args = servicecheck["args"].as_str().unwrap();
            let plugin_name = servicecheck["plugin"]["name"].as_str().unwrap();
            let command = format!("{} {}", plugin_name, args);
            let harmonized_command = harmonize_opspack_variables(&command).unwrap();
            let c = CheckBuilder::new()
                .name(&harmonized_name)
                .command(&harmonized_command)
                .build_raw();
            checks.push(c);
        }
        Ok(Self {
            name: v["hosttemplate"][0]["name"].as_str().unwrap().to_string(),
            description: v["hosttemplate"][0]["description"]
                .as_str()
                .unwrap()
                .to_string(),
            checks,
        })
    }

    pub fn to_xtender_template(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut output = serde_yaml::to_string(&self)?;
        output = output
            .replace("name:", "# name:")
            .replace("description:", "# description:");

        let mut checks_yaml = serde_yaml::to_string(&self.checks)?;

        // Sometimes, checks get wrapped in single quotes. This means that all single quotes
        // already in the command double. We need to remove the surrounding single quotes as well
        // as all the double single quotes.
        //
        // The wrapping seems to be caused by a Nagios range containing : in the command.

        let some_line_starts_and_ends_with_single_quote =
            regex::Regex::new(r"command: '[^\n]+['+\n|'+$]")?;
        if some_line_starts_and_ends_with_single_quote.is_match(&checks_yaml) {
            let mut lines = checks_yaml
                .split('\n')
                .map(|l| l.to_string())
                .collect::<Vec<String>>();
            for line in &mut lines {
                if line.starts_with("  command: '") && line.ends_with('\'') {
                    line.replace_range(11..12, "");
                    line.replace_range(line.len() - 1..line.len(), "");
                }
                *line = line.replace("''", "'");
            }

            checks_yaml = lines.join("\n");
        }

        output.push_str(&checks_yaml);
        output = output.replace("command:", "command: |\n   ");
        output = output.replace("\n  timeout: 5", "");
        output.trim_end().to_string();
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_from_json() {
        let json = r#"{
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
      "name": "Check HTTP A",
      "args": "-H $HOSTADDRESS$ -a /",
      "plugin": {
        "name": "check_http"
      }
    },
    {
      "name": "Check HTTP B",
      "args": "-H $HOSTADDRESS$ -b /",
      "plugin": {
        "name": "check_http"
      }
    }
  ]
}"#;
        let opspack = Opspack::from_json(json).unwrap();
        assert_eq!(opspack.name, "Check HTTP");
        assert_eq!(opspack.description, "Check HTTP");
        assert_eq!(opspack.checks.len(), 2);
        assert_eq!(opspack.checks[0].name(), "Check HTTP A");
        assert_eq!(
            opspack.checks[0].secret_command_or_command(),
            "check_http -H $HOSTADDRESS$ -a /"
        );
        assert_eq!(opspack.checks[1].name(), "Check HTTP B");
        assert_eq!(
            opspack.checks[1].secret_command_or_command(),
            "check_http -H $HOSTADDRESS$ -b /"
        );
    }

    #[test]
    fn test_to_xtender_template() {
        let json = r#"{
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
}
"#;
        let opspack = Opspack::from_json(json).unwrap();
        let template = opspack.to_xtender_template().unwrap();
        let expected_template = r#"# name: Check HTTP
# description: Check HTTP
- name: Check HTTP
  command: |
    check_http -H $HOSTADDRESS_1$ -u $URL_1$
"#;
        assert_eq!(template, expected_template);
    }

    #[test]
    fn test_opspack_without_servicechecks() {
        let json = r#"{
   "attribute" : [
      {
         "arg1" : "",
         "arg2" : "",
         "arg3" : "",
         "arg4" : "",
         "label1" : "Username",
         "label2" : "Password",
         "label3" : "",
         "label4" : "",
         "name" : "WINLDAP_CREDENTIALS",
         "secured1" : "0",
         "secured2" : "1",
         "secured3" : "0",
         "secured4" : "0",
         "value" : "Windows LDAP credentials"
      }
   ]
}
"#;

        let opspack = Opspack::from_json(json);
        assert!(opspack.is_err());
    }

    #[test]
    fn test_application_rabbitmq_node() {
        let json = r#"{
   "attribute" : [
      {
         "arg1" : "guest",
         "arg3" : "",
         "arg4" : "15672",
         "label1" : "Username",
         "label2" : "Password",
         "label3" : "Node Name",
         "label4" : "Port",
         "name" : "RABBITMQ_CREDENTIALS",
         "secured1" : "0",
         "secured2" : "1",
         "secured3" : "0",
         "secured4" : "0",
         "value" : ""
      }
   ],
   "hosttemplate" : [
      {
         "description" : "Monitoring of a RabbitMQ node",
         "has_icon" : "0",
         "managementurls" : [],
         "name" : "Application - RabbitMQ - Node",
         "servicechecks" : [
            {
               "event_handler" : null,
               "exception" : null,
               "name" : "RabbitMQ - Sockets Left",
               "timed_exception" : null
            }
         ]
      }
   ],
   "keyword" : [],
   "servicecheck" : [
      {
         "alert_from_failure" : "1",
         "args" : "-H $HOSTADDRESS$ -m sockets_left -w 1000: -c 500: -P '%RABBITMQ_CREDENTIALS:4%' -u '%RABBITMQ_CREDENTIALS:1%' -p '%RABBITMQ_CREDENTIALS:2%' -n '%RABBITMQ_CREDENTIALS:3%'",
         "attribute" : {
            "name" : "RABBITMQ_CREDENTIALS"
         },
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
         "description" : "File descriptors available for use as sockets remaining",
         "event_handler" : "",
         "event_handler_always_exec" : "0",
         "flap_detection_enabled" : "1",
         "invertresults" : "0",
         "keywords" : [],
         "label" : null,
         "level" : 0,
         "markdown_filter" : "0",
         "name" : "RabbitMQ - Sockets Left",
         "notification_interval" : null,
         "notification_options" : "w,c,r,u,f",
         "oid" : null,
         "plugin" : {
            "name" : "check_rabbitmq_node"
         },
         "retry_check_interval" : "60",
         "sensitive_arguments" : "1",
         "servicegroup" : {
            "name" : "Application - RabbitMQ - Node"
         },
         "snmptraprules" : [],
         "stale_state" : "3",
         "stale_text" : "UNKNOWN: Service results are stale",
         "stale_threshold_seconds" : "1800",
         "stalking" : "",
         "volatile" : "0",
         "warning_comparison" : null,
         "warning_value" : null
      },
      {
         "alert_from_failure" : "1",
         "args" : "-H $HOSTADDRESS$ -m sockets_used_percent -w 70 -c 80 -P '%RABBITMQ_CREDENTIALS:4%' -u '%RABBITMQ_CREDENTIALS:1%' -p '%RABBITMQ_CREDENTIALS:2%' -n '%RABBITMQ_CREDENTIALS:3%'",
         "attribute" : {
            "name" : "RABBITMQ_CREDENTIALS"
         },
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
         "description" : "Percentage of file descriptors used as sockets",
         "event_handler" : "",
         "event_handler_always_exec" : "0",
         "flap_detection_enabled" : "1",
         "invertresults" : "0",
         "keywords" : [],
         "label" : null,
         "level" : 0,
         "markdown_filter" : "0",
         "name" : "RabbitMQ - Sockets Used - percent",
         "notification_interval" : null,
         "notification_options" : "w,c,r,u,f",
         "oid" : null,
         "plugin" : {
            "name" : "check_rabbitmq_node"
         },
         "retry_check_interval" : "60",
         "sensitive_arguments" : "1",
         "servicegroup" : {
            "name" : "Application - RabbitMQ - Node"
         },
         "snmptraprules" : [],
         "stale_state" : "3",
         "stale_text" : "UNKNOWN: Service results are stale",
         "stale_threshold_seconds" : "1800",
         "stalking" : "",
         "volatile" : "0",
         "warning_comparison" : null,
         "warning_value" : null
      }
    ]
}
"#;

        let opspack = Opspack::from_json(json).unwrap();
        let template = opspack.to_xtender_template().unwrap();
        let expected_template = r#"# name: Application - RabbitMQ - Node
# description: Monitoring of a RabbitMQ node
- name: RabbitMQ - Sockets Left
  command: |
    check_rabbitmq_node -H $HOSTADDRESS$ -m sockets_left -w 1000: -c 500: -P '$RABBITMQ_CREDENTIALS_4$' -u '$RABBITMQ_CREDENTIALS_1$' -p '$RABBITMQ_CREDENTIALS_2$' -n '$RABBITMQ_CREDENTIALS_3$'
- name: RabbitMQ - Sockets Used - percent
  command: |
    check_rabbitmq_node -H $HOSTADDRESS$ -m sockets_used_percent -w 70 -c 80 -P '$RABBITMQ_CREDENTIALS_4$' -u '$RABBITMQ_CREDENTIALS_1$' -p '$RABBITMQ_CREDENTIALS_2$' -n '$RABBITMQ_CREDENTIALS_3$'
"#;

        assert_eq!(template, expected_template);
    }
}
