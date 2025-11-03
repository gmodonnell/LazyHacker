function Invoke-TargetedNmapScan {
    # Step 1: Extract open ports from port_scan.gnmap
    $openPorts = Get-Content "port_scan.gnmap" | 
        Select-String "/open/" | 
        ForEach-Object { 
            $_.Line.Split(" ", 4)[3].Split(",") | 
            ForEach-Object { $_.Split("/")[0] } 
        } | 
        Sort-Object -Unique

    # Save open ports to file
    $openPorts | Set-Content "open_ports.txt"

    # Grab Unique discovered ports
    $portsString = ($openPorts | Select-Object -Unique) -join ','

    # Step 3: Run targeted nmap scan
    Write-Host "Phase 3: Targeted script scan..." -ForegroundColor Green
    $nmapArgs = @(
        "-sV",                  # Version detection
        "--unprivileged",
        "-Pn"
        "-sC",                  # Default script scan
        "-p", $portsString,     # Specify open ports
        "-oA", "service_scan",     # Output all formats with prefix "nmap_scan"
        "-iL", ".\scanparse\up.txt" # Input from live hosts file
    )

    # Execute nmap
    & nmap.exe $nmapArgs

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Nmap targeted scan completed successfully." -ForegroundColor Green
    } else {
        Write-Host "Nmap targeted scan failed with exit code: $LASTEXITCODE" -ForegroundColor Red
    }
}

# Run the function
Invoke-TargetedNmapScan