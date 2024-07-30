param (
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

# Function to parse the service string
function Parse-Service {
    param (
        [string]$serviceString
    )
    if ($serviceString -match '//(.+?)//') {
        return $matches[1].Trim()
    }
    return $serviceString
}

# Read the file content
$content = Get-Content -Path $FilePath -Raw

# Split the content into lines
$lines = $content -split "`n"

# Create an array to store the results
$results = @()

# Process each line
foreach ($line in $lines) {
    if ($line -match 'Ports:') {
        # Extract IP address
        $ip = $line -replace 'Host:\s*(\S+)\s.*', '$1'
        
        # Extract ports information
        $portsInfo = $line -replace '.*Ports:\s*', ''
        
        # Split ports information
        $ports = $portsInfo -split ',\s*'
        
        foreach ($port in $ports) {
            if ($port -match '(\d+)/open/tcp//(.+)') {
                $portNumber = $matches[1]
                $service = Parse-Service -serviceString $matches[2]
                
                # Add to results
                $results += [PSCustomObject]@{
                    IP = $ip
                    Port = $portNumber
                    Service = $service
                }
            }
        }
    }
}

# Export to CSV
$outputPath = "nmap_results.csv"
$results | Export-Csv -Path $outputPath -NoTypeInformation

Write-Host "CSV file has been created at: $outputPath"