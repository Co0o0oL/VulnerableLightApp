<#
.SYNOPSIS
    This script manages WebInspect scans, waits for running scans to complete, and uploads results to SSC.
.PARAMETER scanName
    The name of the scan to be created.
.PARAMETER scanURL
    The target URL for the scan.
.PARAMETER crawlAuditMode
    The mode for the crawl and audit (e.g., 'CrawlandAudit').
.PARAMETER loginMacro
    Optional login macro to use during the scan.
.PARAMETER settingsName
    Settings profile name for the scan. Default is 'Default'.
.PARAMETER wiAPIurl
    Base URL for the WebInspect API.
.PARAMETER sscURL
    Base URL for the SSC API.
.PARAMETER applicationVersionID
    Application version ID in SSC.
.PARAMETER sscToken
    Authentication token for SSC.
.PARAMETER pollInterval
    Interval (in seconds) to check the scan status. Default is 20 seconds.
.DESCRIPTION
    This script starts a WebInspect scan, waits for its completion, downloads the scan results, and uploads them to SSC.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$scanName,

    [Parameter(Mandatory = $true)]
    [string]$scanURL,

    [Parameter(Mandatory = $true)]
    [string]$crawlAuditMode,

    [string]$loginMacro = $null,  # Optional parameter

    [string]$settingsName = 'Default',

    [string]$wiAPIurl = 'http://fortify:8083/webinspect/api/v1/',

    [string]$sscURL = 'http://localhost/ssc/',

    [Parameter(Mandatory = $true)]
    [string]$applicationVersionID,

    [Parameter(Mandatory = $true)]
    [string]$sscToken,

    [int]$pollInterval = 20
)

# Function to check the status of running scans
function Get-ScanStatus {
    $response = Invoke-RestMethod -Uri "$wiAPIurl/scanner/scans?Status=running" -Method Get -Headers @{ 'Accept' = 'application/json' }
    return $response
}

# Function to start a new scan
function Start-Scan {
    param (
        [string]$scanName,
        [string]$scanURL,
        [string]$crawlAuditMode,
        [string]$loginMacro = $null  # Optional parameter
    )
    
    $body = @{
        settingsName = $settingsName
        overrides = @{
            scanName = $scanName
            startUrls = @($scanURL)
            crawlAuditMode = $crawlAuditMode
            startOption = "Url"
        }
    }

    # Add LoginMacro to body if it is provided
    if ($null -ne $loginMacro) {
        $body.overrides.LoginMacro = $loginMacro
    }

    $bodyJson = $body | ConvertTo-Json

    $responseurl = "$wiAPIurl/scanner/scans"
    $response = Invoke-RestMethod -Method POST -ContentType "application/json" -Body $bodyJson -Uri $responseurl

    return $response.ScanId
}

# Function to check the status of the scan until it's completed, stopped, or interrupted
function Wait-For-ScanCompletion {
    param (
        [string]$scanId
    )

    $StatusUrl = "$wiAPIurl/scanner/scans/$scanId/log"
    $ScanCompleted = "ScanCompleted"
    $ScanStopped = "ScanStopped"
    $ScanInterrupted = "ScanInterrupted"

    do {
        $status = Invoke-RestMethod -Method GET -ContentType "application/json" -Uri $StatusUrl
        $ScanDate = $status[-1].Date
        $ScanMessage = $status[-1].Message
        $ScanStatus = $status[-1].Type
        Write-Host ($ScanDate, $ScanMessage, $ScanStatus) -Separator " - "
        Start-Sleep -Seconds $pollInterval
    } while (($ScanStatus -ne $ScanCompleted) -and ($ScanStatus -ne $ScanStopped) -and ($ScanStatus -ne $ScanInterrupted))

    return $ScanStatus
}

# Function to download the scan result in FPR format
function Download-ScanResults {
    param (
        [string]$scanId
    )

    $fprurl = "$wiAPIurl/scanner/scans/$scanId.fpr"
    $path = "$scanId.fpr"

    Write-Host ("Downloading the result file (fpr)...")
    Invoke-RestMethod -Method GET -OutFile $path -Uri $fprurl
    Write-Host -ForegroundColor Green ("Result file (fpr) download done!") `n
    Write-Host "Downloaded FPR to: $path"  # Print the path to console

    return $path
}

# Function to upload the scan results to SSC
function Upload-ScanResults {
    param (
        [string]$fprPath
    )

    Write-Host ("Starting Upload to SSC...")
    Write-Host "Uploading FPR file from: $fprPath"  # Print the path to console
    $response = fortifyclient -url $sscURL -applicationVersionID $applicationVersionID -authtoken $sscToken uploadFPR -f $fprPath
    Write-Host -ForegroundColor Green ("Finished! Scan Results are now available in the Software Security Center!")
}

# Function to check if there are any running scans
function Check-For-RunningScans {
    $scanStatus = Get-ScanStatus
    Write-Host "Raw API response:"
    $scanStatus | ConvertTo-Json | Write-Host

    return $scanStatus
}

# Function to monitor the running scan and wait until it's completed before starting a new scan
function Monitor-And-WaitFor-ScanToFinish {
    while ($true) {
        $scanStatus = Get-ScanStatus

        # If no scans are running, exit the loop to start a new scan
        if ($scanStatus.Count -eq 0) {
            Write-Host "No running scan detected, proceeding to start a new scan."
            break
        } else {
            Write-Host "A scan is still running. Checking again in $pollInterval seconds..."
            Start-Sleep -Seconds $pollInterval
        }
    }
}

# Main script execution
Monitor-And-WaitFor-ScanToFinish  # Monitor the scan until no scans are running

# Start the scan
$scanId = Start-Scan -scanName $scanName -scanURL $scanURL -crawlAuditMode $crawlAuditMode -loginMacro $loginMacro

Write-Host -ForegroundColor Green ("Scan started successfully with Scan Id: " + $scanId)

# Wait for the scan to complete
$ScanStatus = Wait-For-ScanCompletion -scanId $scanId

if ($ScanStatus -eq "ScanCompleted") {
    Write-Host -ForegroundColor Green ("Scan completed!") `n

    # Download the results
    $fprPath = Download-ScanResults -scanId $scanId

    # Upload the results to SSC
    Upload-ScanResults -fprPath $fprPath
} else {
    Write-Host -ForegroundColor Red ("Error occurred after Scan was finished!")
}


### .\WI_param.ps1 -scanName test -scanURL https://example.com -crawlAuditMode CrawlandAudit -applicationVersionID 10031 -sscToken YWYxZGM3ODEtODAxMi00YjU0LWJjNDgtZjA1MTY4YzVkM2Mw -sscURL http://51.89.84.147/ssc