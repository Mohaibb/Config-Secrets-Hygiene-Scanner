Config & Secrets Hygiene Scanner — Notes


What I Implemented:


•	Built a PowerShell 7.4 scanner to evaluate the supplied JSON and YAML configuration files against the eight security requirements.
•	Added consistent findings containing the filename, location, rule, severity, explanation and suggested fix.
•	Introduced a separate Not Evaluated category for missing FTP/SCM publishing settings under RULE-007, demonstrating how the scanner can distinguish between insecure configurations and settings that cannot be confidently assessed.
•	Used JSON parsing and regex-based YAML checks to detect insecure settings and potential hardcoded credentials without exposing secret values in findings.
•	Completed the stretch goal by adding optional file path parameters and testing the scanner against differently named files with modified configuration values.
•	Saved baseline, custom-file and modified-value test results in the test-evidence folder.
•	Added basic error handling using try/catch amd input validation to stop the scanner when JSON configuration files cannot be loaded or parsed, or when the YAML file is missing.


What I Deliberately Left Out:


•	Full YAML parsing and support for complex or multi-line pipeline structures, opting for regex matching due to the time constraint.
•	Comprehensive automated testing across every rule and edge case.
•	Support for arbitrary configuration schemas beyond the recognised structures and patterns.
•	Full Azure DevOps pipeline integration and structured reporting formats.


What I Would Improve With More Time:


•	Introduce configuration-driven security rules, allowing authorised teams to update thresholds and supported rule settings without modifying the main PowerShell script, with changes controlled through pull requests and approvals.
•	Extend the Not Evaluated handling demonstarted in RULE-007 across the remaining applicable security checks, ensuring missing or unsupported configuration settings are reported rather than silently skipped.
•	Add Pester unit tests and expand positive and negative test coverage across all eight rules.
•	Improve YAML parsing and secret detection to reduce false positives and false negatives.
•	Refactor the scanner into smaller, reusable functions or modules.
•	Add JSON/SARIF reporting, pipeline exit codes and Azure DevOps integration.


Copilot Usage:


•	Used GitHub Copilot throughout development for PowerShell implementation guidance, rule development, troubleshooting and reviewing different approaches.
•	Challenged Copilot’s suggestion to compare TLS versions using [double]. I chose [version] instead because TLS values represent version numbers rather than decimals, making it a more appropriate approach.
•	Reviewed Copilot’s suggestions around recognising placeholder passwords such as changeme and password123. I decided against relying on a list of known placeholders because a real hardcoded credential could be missed simply because it doesn’t match one of those values.
•	Considered the risk of false positives when detecting credentials, particularly where values reference Azure Key Vault or pipeline variables rather than containing hardcoded secrets.
•	Used Copilot as a development aid rather than blindly accepting its suggestions, reviewing the proposed logic and making changes based on my own understanding of the requirements and security implications.
