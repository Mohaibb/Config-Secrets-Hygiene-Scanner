param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "appsettings.sample.json"),
    [string]$PipelinePath = (Join-Path $PSScriptRoot "azure-pipelines.sample.yml")
)

function New-Finding {
    param(
        [string]$File,
        [string]$Location,
        [string]$RuleId,
        [string]$Rule,
        [ValidateSet('High', 'Medium', 'Low')]
        [string]$Severity,
        [string]$Message,
        [string]$SuggestedFix
    )

    [PSCustomObject]@{
        File         = $File
        Location     = $Location
        RuleId       = $RuleId
        Rule         = $Rule
        Severity     = $Severity
        Message      = $Message
        SuggestedFix = $SuggestedFix
    }
}

$ConfigFileName = Split-Path $ConfigPath -Leaf

try {
    $RawContent = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
    $config = $RawContent | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Write-Error "Failed to read or parse the configuration file: $($_.Exception.Message)"
    exit 1
}

$Findings = @()
$NotEvaluated = @()

if ($config.Network.PublicNetworkAccess -eq "Enabled") {
    $FindingDetails = @{
        File         = $ConfigFileName
        Location     = "Network.PublicNetworkAccess"
        RuleID       = "RULE-002"
        Rule         = "Public network access must be disbaled"
        Severity     = "High"
        Message      = "Public network access is enabled"
        SuggestedFix = "Disable public network access"
    }

    $Findings += New-Finding @FindingDetails
}

if ($config.Security.HttpsOnly -eq $false) {
    $FindingDetails = @{
        File         = $ConfigFileName
        Location     = "Security.HttpsOnly"
        RuleID       = "RULE-004"
        Rule         = "HTTPS must be enforced"
        Severity     = "High"
        Message      = "HttpsOnly is disabled"
        SuggestedFix = "Set Security.HttpsOnly to true"
    }

    $Findings += New-Finding @FindingDetails
}

if ([version]$config.Security.MinimumTlsVersion -lt [version]"1.2") {
    $FindingDetails = @{
        File         = $ConfigFileName
        Location     = "Security.MinimumTlsVersion"
        RuleID       = "RULE-003"
        Rule         = "TLS minimum version must be >= 1.2"
        Severity     = "High"
        Message      = "Minimum TLS version is $($config.Security.MinimumTlsVersion)"
        SuggestedFix = "Set Security.MinimumTlsVersion to 1.2 or higher"
    }

    $Findings += New-Finding @FindingDetails
}

if ($config.Ftp.Enabled -eq $true) {
    $FindingDetails = @{
        File         = $ConfigFileName
        Location     = "Ftp.Enabled"
        RuleID       = "RULE-005"
        Rule         = "FTP/FTPS must be disabled"
        Severity     = "High"
        Message      = "FTP is enabled"
        SuggestedFix = "Set Ftp.Enabled to false"
    }

    $Findings += New-Finding @FindingDetails
}

if ($config.Debugging.RemoteDebuggingEnabled -eq $true) {
    $FindingDetails = @{
        File         = $ConfigFileName
        Location     = "Debugging.RemoteDebuggingEnabled"
        RuleID       = "RULE-006"
        Rule         = "Remote debugging must be disabled"
        Severity     = "High"
        Message      = "Remote debugging is enabled"
        SuggestedFix = "Set Debugging.RemoteDebuggingEnabled to false"
    }

    $Findings += New-Finding @FindingDetails
}

if ($config.Logging.SendToLogAnalytics -eq $false) {
    $FindingDetails = @{
        File         = $ConfigFileName
        Location     = "Logging.SendToLogAnalytics"
        RuleID       = "RULE-008"
        Rule         = "Diagnostic logging must be enabled and sent to Log Analytics"
        Severity     = "Medium"
        Message      = "Diagnostic logging is not sent to Log Analytics"
        SuggestedFix = "Set Logging.SendToLogAnalytics to true"
    }

    $Findings += New-Finding @FindingDetails
}

if ($null -eq $config.Publishing.FtpBasicAuthEnabled) {
    $NotEvaluated += "RULE-007 FTP: Not evaluated - setting missing (Publishing.FtpBasicAuthEnabled)"
}
elseif ($config.Publishing.FtpBasicAuthEnabled -eq $true) {
    $FindingDetails = @{
        File         = $ConfigFileName
        Location     = "Publishing.FtpBasicAuthEnabled"
        RuleID       = "RULE-007"
        Rule         = "Basic publishing credentials (FTP/SCM) must be disabled"
        Severity     = "High"
        Message      = "FTP basic publishing credentials are enabled"
        SuggestedFix = "Set Publishing.FtpBasicAuthEnabled to false"
    }

    $Findings += New-Finding @FindingDetails
}

if ($null -eq $config.Publishing.ScmBasicAuthEnabled) {
    $NotEvaluated += "RULE-007 SCM: Not evaluated - setting missing (Publishing.ScmBasicAuthEnabled)"
}
elseif ($config.Publishing.ScmBasicAuthEnabled -eq $true) {
    $FindingDetails = @{
        File         = $ConfigFileName
        Location     = "Publishing.ScmBasicAuthEnabled"
        RuleID       = "RULE-007"
        Rule         = "Basic publishing credentials (FTP/SCM) must be disabled"
        Severity     = "High"
        Message      = "SCM basic publishing credentials are enabled"
        SuggestedFix = "Set Publishing.ScmBasicAuthEnabled to false"
    }

    $Findings += New-Finding @FindingDetails
}

# references like $(var) or @Microsoft.KeyVault(...) are not hardcoded secrets
$SecretPlaceholderPattern = '^\$\(.*\)$|^@Microsoft\.KeyVault\(.*\)$|(?i)^(placeholder)$'

foreach ($property in $config.ConnectionStrings.PSObject.Properties) {
    if ($property.Value -match '(?i)(password|pwd)\s*=\s*([^;]+)') {
        $SecretValue = $Matches[2]
        if ($SecretValue -and $SecretValue -notmatch $SecretPlaceholderPattern) {
            $FindingDetails = @{
                File         = $ConfigFileName
                Location     = "ConnectionStrings.$($property.Name)"
                RuleID       = "RULE-001"
                Rule         = "No hardcoded secrets/passwords/API keys/connection string credentials"
                Severity     = "High"
                Message      = "Connection string contains a hardcoded password"
                SuggestedFix = "Move the password to Key Vault and reference it instead of hardcoding"
            }

            $Findings += New-Finding @FindingDetails
        }
    }
}

foreach ($property in $config.ApiKeys.PSObject.Properties) {
    if ($property.Value -and $property.Value -notmatch $SecretPlaceholderPattern) {
        $FindingDetails = @{
            File         = $ConfigFileName
            Location     = "ApiKeys.$($property.Name)"
            RuleID       = "RULE-001"
            Rule         = "No hardcoded secrets/passwords/API keys/connection string credentials"
            Severity     = "High"
            Message      = "API key is hardcoded in configuration"
            SuggestedFix = "Move the API key to Key Vault and reference it instead of hardcoding"
        }

        $Findings += New-Finding @FindingDetails
    }
}

if (-not (Test-Path -Path $PipelinePath -PathType Leaf)) {
    Write-Error "Pipeline file not found: $PipelinePath"
    exit 1
}
$PipelineFileName = Split-Path $PipelinePath -Leaf

# TODO: broad keyword match - may need tightening (e.g. require :/= or exclude comments) to reduce false positives
$SuspiciousLines = Select-String -Path $PipelinePath -Pattern '(?i)(password|pwd|secret|apikey|api_key|-P\s)'

foreach ($SuspiciousLine in $SuspiciousLines) {
    $Line = $SuspiciousLine.Line
    $LineNumber = $SuspiciousLine.LineNumber

    if ($Line -match '(?i)(password|pwd|secret|apikey|api_key)\w*\s*[:=]\s*[''"]?([^''"\s]+)') {
        $Token = $Matches[2]
    }
    elseif ($Line -match '(?i)-P\s+[''"]?([^''"\s]+)') {
        $Token = $Matches[1]
    }
    else {
        $Token = $Line.Trim()
    }

    if ($Token -notmatch $SecretPlaceholderPattern) {
        $FindingDetails = @{
            File         = $PipelineFileName
            Location     = "Line $LineNumber"
            RuleID       = "RULE-001"
            Rule         = "No hardcoded secrets/passwords/API keys/connection string credentials"
            Severity     = "High"
            Message      = "Potential hardcoded credential requiring review"
            SuggestedFix = "Move the value to a Key Vault-linked variable group instead of hardcoding"
        }

        $Findings += New-Finding @FindingDetails
    }
}

$TlsLines = Select-String -Path $PipelinePath -Pattern '(?i)--min-tls-version\s+[''"]?TLS(\d_\d)'

foreach ($TlsLine in $TlsLines) {
    $TlsVersionString = $TlsLine.Matches[0].Groups[1].Value -replace '_', '.'

    if ([version]$TlsVersionString -lt [version]"1.2") {
        $FindingDetails = @{
            File         = $PipelineFileName
            Location     = "Line $($TlsLine.LineNumber)"
            RuleID       = "RULE-003"
            Rule         = "TLS minimum version must be >= 1.2"
            Severity     = "High"
            Message      = "Minimum TLS version is below 1.2"
            SuggestedFix = "Set --min-tls-version to TLS1_2 or higher"
        }

        $Findings += New-Finding @FindingDetails
    }
}

$Findings | Format-List
$NotEvaluated