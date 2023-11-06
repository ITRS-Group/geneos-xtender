use clap::Parser;
use geneos_xtender::check::{
    run_all_checks_in_parallel, run_all_checks_sequentially, CheckBuilder, Checks,
};
use geneos_xtender::opspack::Opspack;
use geneos_xtender::result::ProcessedCheckResultsExt;
use log::debug;
use serde_yaml::Value;
use std::fs;
use std::path::Path;

const ABOUT_XTENDER: &str = r#"
Geneos Xtender:

Run one or more Nagios compatible plugin checks in parallel
and return the results in a format compatible with the Geneos
Toolkit Plugin.

All arguments following -- will be names of, or paths to Xtender
Templates. For templates in the /opt/xtender/templates/ directory,
it's possible to just specify the template name without
the path and the file extension.

The file format for Xtender Templates is YAML and the format is:
- name: <name>
  command: |
    <command with args>
  timeout: <timeout> # (optional)

Example command that runs all checks contained in the templates
"network-base" and a custom template located at
/path/to/other/template.yaml:

$ xtender -- network-base /path/to/other/template.yaml
"#;

const DEFAULT_TIMEOUT: u64 = 5;

const INVALID_YAML_SEQ_ERROR_MSG: &str = r#"
The parsed Xtender Template yaml string is not a valid sequence.
Make sure that each entry in the template follows this format:
- name: <name>
  timeout: <timeout> # (optional)
  command: |
    <command with args>
"#;

const TEMPLATES_DIR: &str = "/opt/xtender/templates/";
const CUSTOM_TEMPLATES_DIR: &str = "/opt/xtender/templates/custom/";

#[derive(Parser, Debug, Default)]
#[command(about = ABOUT_XTENDER, author, version, long_about = None)]
struct Args {
    /// Xtender Tempates containing checks to run in parallel
    #[arg(required = true, last = true)]
    templates: Option<Vec<String>>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    /// Convert an Opspack JSON file to an Xtender Template and print the result to stdout
    #[arg(short, long, exclusive = true)]
    opspack: Option<String>,

    /// Run checks sequentially instead of in parallel
    #[arg(short, long)]
    sequential: bool,
}

struct ParsedTemplates {
    found: Vec<String>,
    missing: Vec<String>,
    strings: Vec<String>,
}

impl ParsedTemplates {
    fn new() -> Self {
        Self {
            found: Vec::new(),
            missing: Vec::new(),
            strings: Vec::new(),
        }
    }

    fn add_found(&mut self, template: &str, template_string: String) {
        self.found.push(template.to_string());
        self.strings.push(template_string);
    }

    fn add_missing(&mut self, template: &str) {
        self.missing.push(template.to_string());
    }

    fn from_template_names(template_names: &[String]) -> Self {
        let mut parsed_templates = Self::new();
        for template_name in template_names {
            if let Ok(t) = find_and_read_template(template_name) {
                parsed_templates.add_found(template_name, t);
            } else {
                parsed_templates.add_missing(template_name);
            }
        }
        parsed_templates
    }
}

#[tokio::main]
async fn main() {
    let parsed_args = Args::parse();

    stderrlog::new()
        .module(module_path!())
        .verbosity(if parsed_args.debug { 4 } else { 0 })
        .init()
        .unwrap();

    if let Some(opspack_file) = parsed_args.opspack {
        let opspack_json = fs::read_to_string(&opspack_file)
            .unwrap_or_else(|_| panic!("Failed to read file: {}", opspack_file));
        let o = Opspack::from_json(&opspack_json);
        let t = o.unwrap_or_else(|e| panic!("{}", e)).to_xtender_template();
        print!("{}", t);
        std::process::exit(0);
    }

    let mut checks = Checks::new();
    let mut parsed_templates = ParsedTemplates::new();

    if let Some(template_names) = parsed_args.templates.clone() {
        parsed_templates = ParsedTemplates::from_template_names(&template_names);

        for template in &parsed_templates.strings {
            let template_yaml: Value =
                serde_yaml::from_str(template).expect("Failed to parse yaml template from string");

            let yaml_checks_vec = template_yaml
                .as_sequence()
                .expect(INVALID_YAML_SEQ_ERROR_MSG);

            for check in yaml_checks_vec {
                let check_map = check
                    .as_mapping()
                    .unwrap_or_else(|| panic!("The check is not a valid mapping: {:?}", check));

                let c = CheckBuilder::new()
                    .name(&yaml_or_panic(check_map, "name"))
                    .command(&yaml_or_panic(check_map, "command"))
                    .timeout(
                        match check_map.get(&serde_yaml::Value::String("timeout".to_string())) {
                            Some(t) => t.as_u64().expect("The timeout is not a valid u64"),
                            None => DEFAULT_TIMEOUT,
                        },
                    )
                    .build();

                let range_checks = c.expand_ranges();

                for rc in range_checks {
                    checks.push(rc);
                }
            }
        }
    }

    debug!("Finished parsing checks: {:#?}", checks);

    let results = if parsed_args.sequential {
        debug!("Running checks sequentially");
        match run_all_checks_sequentially(checks)
            .unwrap()
            .process()
            .as_csv_string()
        {
            Ok(s) => s,
            Err(e) => panic!("Unable to generate CSV string with error: {}", e),
        }
    } else {
        debug!("Running checks in parallel");
        match run_all_checks_in_parallel(checks)
            .await
            .unwrap()
            .process()
            .as_csv_string()
        {
            Ok(s) => s,
            Err(e) => panic!("Unable to generate CSV string with error: {}", e),
        }
    };

    let results_with_headline =
        with_templates_in_headline(&results, &parsed_templates.found, &parsed_templates.missing);

    print!("{}", results_with_headline);
    std::process::exit(0);
}

fn with_templates_in_headline(
    results: &str,
    found_templates: &[String],
    missing_templates: &[String],
) -> String {
    let found_msg = format!("<!>templatesFound,{}", found_templates.join(", "));
    let missing_msg = format!("<!>templatesNotFound,{}", missing_templates.join(", "));

    let mut results_vec: Vec<&str> = results.split('\n').collect();

    results_vec.insert(1, &missing_msg);
    results_vec.insert(1, &found_msg);

    results_vec.join("\n")
}

fn is_valid_path(path: &str) -> bool {
    Path::new(path).exists()
}

fn is_yaml_file(path: &str) -> bool {
    path.ends_with(".yaml") || path.ends_with(".yml")
}

fn find_and_read_template(template: &str) -> std::io::Result<String> {
    if is_valid_path(template) && is_yaml_file(template) {
        fs::read_to_string(template)
    } else {
        let dist_yaml_path = format!("{}{}.yaml", TEMPLATES_DIR, template);
        let dist_yml_path = format!("{}{}.yml", TEMPLATES_DIR, template);
        let custom_yaml_path = format!("{}{}.yaml", CUSTOM_TEMPLATES_DIR, template);
        let custom_yml_path = format!("{}{}.yml", CUSTOM_TEMPLATES_DIR, template);

        // Look for the template in the custom directory first, so that the user can override
        // a template by placing a modified copy in the custom directory.
        if let Ok(template_string) = fs::read_to_string(&custom_yaml_path) {
            debug!("Found template file: {}", &custom_yaml_path);
            Ok(template_string)
        } else if let Ok(template_string) = fs::read_to_string(&custom_yml_path) {
            debug!("Found template file: {}", &custom_yml_path);
            Ok(template_string)
        } else if let Ok(template_string) = fs::read_to_string(&dist_yaml_path) {
            debug!("Found template file: {}", &dist_yaml_path);
            Ok(template_string)
        } else if let Ok(template_string) = fs::read_to_string(&dist_yml_path) {
            debug!("Found template file: {}", &dist_yml_path);
            Ok(template_string)
        } else {
            debug!(
                "Unable to find template file in standard directories, trying as path: {}",
                template
            );

            Ok(fs::read_to_string(template)?)
        }
    }
}

fn yaml_to_optional_string(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(&serde_yaml::Value::String(key.to_string()))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .map(|s| s.to_string())
}

fn yaml_or_panic(map: &serde_yaml::Mapping, key: &str) -> String {
    yaml_to_optional_string(map, key)
        .unwrap_or_else(|| panic!("Unable to parse {} in check: {:?}", key, map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yaml_to_str() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
        foo: bar
        baz: qux
    "#,
        )
        .unwrap();

        let map = yaml.as_mapping().unwrap();

        assert_eq!(yaml_to_optional_string(map, "foo"), Some("bar".to_string()));
        assert_eq!(yaml_to_optional_string(map, "baz"), Some("qux".to_string()));
    }

    #[test]
    fn test_yaml_to_str_missing_key() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
        foo: bar
        baz: qux
    "#,
        )
        .unwrap();

        let map = yaml.as_mapping().unwrap();

        assert_eq!(yaml_to_optional_string(map, "missing"), None);
    }

    #[test]
    fn test_yaml_or_panic() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
        foo: bar
        baz: qux
    "#,
        )
        .unwrap();

        let map = yaml.as_mapping().unwrap();

        assert_eq!(yaml_or_panic(map, "foo"), "bar".to_string());
        assert_eq!(yaml_or_panic(map, "baz"), "qux".to_string());
    }

    #[test]
    #[should_panic]
    fn test_yaml_or_panic_missing_key() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
        foo: bar
        baz: qux
    "#,
        )
        .unwrap();

        let map = yaml.as_mapping().unwrap();

        yaml_or_panic(map, "missing");
    }
}
