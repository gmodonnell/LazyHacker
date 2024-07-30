function Invoke-DeHashedQuery {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SearchTerm
    )

    # Check if environment variables are set
    if (-not $env:DEHASHED_USER) {
        Write-Error "Environment Variable DEHASHED_USER not found... Quitting."
        return
    }
    if (-not $env:DEHASHED_API_KEY) {
        Write-Error "Environment Variable DEHASHED_API_KEY not found... Quitting."
        return
    }

    $login = $env:DEHASHED_USER
    $apikey = $env:DEHASHED_API_KEY

    Write-Host "Argument Provided: Querying Dehashed for $SearchTerm" -ForegroundColor Green

    # Invoke REST API Request
    $url = "https://api.dehashed.com/search?query=email:@$SearchTerm&size=10000"
    $pair = "$($login):$($apikey)"
    $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
    $headers = @{
        Authorization = "Basic $encodedCreds"
        Accept = "application/json"
    }

    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

    # Parse and process the results
    $curLength = $response.entries.Length
    Write-Host "$curLength records to parse. Starting Now..."

    $results = @()
    for ($index = 0; $index -lt $curLength; $index++) {
        Write-Progress -Activity "Processing entries" -Status "$index/$curLength" -PercentComplete (($index / $curLength) * 100)
        
        $item = $response.entries[$index]
        $email = $item.email
        $password = $item.password
        $hashed_password = $item.hashed_password
        $database_name = $item.database_name

        if (($password -or $hashed_password) -and $email -and $database_name) {
            $results += [PSCustomObject]@{
                Email = $email
                Password = $password
                HashedPassword = $hashed_password
                DatabaseName = $database_name
            }
        }
    }

    # Export results to CSV
    $results | Export-Csv -Path "dehashedResults.csv" -NoTypeInformation

    # Remove duplicates
    $uniqueResults = $results | Sort-Object Email, Password, HashedPassword, DatabaseName -Unique
    $uniqueResults | Export-Csv -Path "dehashedDeduped.csv" -NoTypeInformation

    Write-Host "Query completed. Results saved in dehashedResults.csv and dehashedDeduped.csv"
}

Invoke-DeHashedQuery