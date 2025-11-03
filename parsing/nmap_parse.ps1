$global:outpath = $null

function Invoke-NmapParse {
    if (-not (Test-Path "nmap_scan.gnmap")) {
        Write-Error "nmap_scan.gnmap file not found in working directory."
        return
    }
    $global:outpath = Join-Path (Get-Location) "scanparse"
    Invoke-MasterCleanup
    Get-Content (Resolve-Path "nmap_scan.gnmap") | Sort-Object | Set-Content "temp.gnmap"
    New-Item -ItemType Directory -Force -Path $global:outpath | Out-Null
    Move-Item "temp.gnmap" $global:outpath
    $inputfilepath = Join-Path $global:outpath "temp.gnmap"
    
    Invoke-MakeCsv
    Invoke-Summary
    Invoke-IpPort
    Invoke-UniquePorts
    Invoke-TcpPorts
    Invoke-UdpPorts
    Invoke-UpHosts
    Invoke-DownHosts
    Invoke-Smb
    Invoke-Web
    Invoke-Ssl
    Invoke-Ssh
    Invoke-HostPorts
    Invoke-ClosedSummary
    Invoke-Report1
    Invoke-MasterCleanup
}

function Invoke-MasterCleanup {
    $filesToRemove = @(
        "tempinput", "ipptemp", "closedtemp", "summtemp", "tempfile", "tempfile2",
        "inputfile", "webtemp", "webtemp2", "hostptemp", "temp.gnmap", "temp.csv", "sshtemp"
    )
    foreach ($file in $filesToRemove) {
        Remove-Item (Join-Path $global:outpath $file) -ErrorAction SilentlyContinue
    }
}

function Invoke-MakeCsv {
    $csvContent = Get-Content $inputfilepath | ForEach-Object {
        if ($_ -match '/open/|/closed/') {
            $endpoint = ($_ -split ' ')[1]
            $ports = ($_ -split ' ')[3..$_.Length] -join ' '
            $ports -split ',' | ForEach-Object {
                if ($_ -match '/open/|/closed/') {
                    $port, $status, $protocol, $service, $version = $_ -split '/'
                    [PSCustomObject]@{
                        Host = $endpoint
                        Port = $port.Trim()
                        Status = $status
                        Protocol = $protocol
                        Service = $service
                        Version = $version
                    }
                }
            }
        }
    } | Sort-Object Host, Port

    $csvContent | Export-Csv -Path (Join-Path $outpath "parsed_nmap.csv") -NoTypeInformation
    Write-Host "       - parsed_nmap.csv"
}

function Invoke-Summary {
    $csvContent = Import-Csv (Join-Path $outpath "parsed_nmap.csv")
    $summary = $csvContent | Group-Object Host | ForEach-Object {
        $endpoint = $_.Name
        $ports = $_.Group | ForEach-Object { "$($_.Port)/$($_.Protocol)" }
        [PSCustomObject]@{
            Host = $endpoint
            Ports = ($ports -join ", ")
        }
    }

    $summary | Format-Table -AutoSize | Out-File (Join-Path $outpath "summary.txt")
    Write-Host "  - summary.txt"
}

function Invoke-IpPort {
    $csvContent = Import-Csv (Join-Path $outpath "parsed_nmap.csv")
    $ipPorts = $csvContent | ForEach-Object { "$($_.Host):$($_.Port)" }
    $ipPorts | Sort-Object -Unique | Set-Content (Join-Path $outpath "ipport.txt")
    Write-Host "  - ipport.txt"
}

function Invoke-UniquePorts {
    $csvContent = Import-Csv (Join-Path $outpath "parsed_nmap.csv")
    $uniquePorts = $csvContent.Port | Sort-Object -Unique
    $uniquePorts -join ',' | Set-Content (Join-Path $outpath "unique.txt")
    Write-Host "  - unique.txt"
}

function Invoke-TcpPorts {
    $csvContent = Import-Csv (Join-Path $outpath "parsed_nmap.csv")
    $tcpPorts = $csvContent | Where-Object { $_.Protocol -eq 'tcp' } | Select-Object -ExpandProperty Port | Sort-Object -Unique
    $tcpPorts -join ',' | Set-Content (Join-Path $outpath "tcp.txt")
    Write-Host "  - tcp.txt"
}

function Invoke-UdpPorts {
    $csvContent = Import-Csv (Join-Path $outpath "parsed_nmap.csv")
    $udpPorts = $csvContent | Where-Object { $_.Protocol -eq 'udp' } | Select-Object -ExpandProperty Port | Sort-Object -Unique
    $udpPorts -join ',' | Set-Content (Join-Path $outpath "udp.txt")
    Write-Host "  - udp.txt"
}

function Invoke-UpHosts {
    $upHosts = Get-Content $inputfilepath | Where-Object { $_ -match 'Status: Up' -or $_ -match '/open/' } | ForEach-Object { ($_ -split ' ')[1] } | Sort-Object -Unique
    $upHosts | Set-Content (Join-Path $outpath "up.txt")
    Write-Host "  - up.txt"
}

function Invoke-DownHosts {
    $downHosts = Get-Content $inputfilepath | Where-Object { $_ -match 'Status: Down' } | ForEach-Object { ($_ -split ' ')[1] } | Sort-Object -Unique
    $downHosts | Set-Content (Join-Path $outpath "down.txt")
    Write-Host "  - down.txt"
}

function Invoke-Smb {
    $csvContent = Import-Csv (Join-Path $outpath "parsed_nmap.csv")
    $smbHosts = $csvContent | Where-Object { $_.Port -eq '445' -and $_.Protocol -eq 'tcp' } | ForEach-Object { "smb://$($_.Host)" }
    $smbHosts | Sort-Object -Unique | Set-Content (Join-Path $outpath "smb.txt")
    Write-Host "  - smb.txt"
}

function Invoke-Web {
    $csvContent = Import-Csv (Join-Path $outpath "parsed_nmap.csv")
    $webHosts = $csvContent | Where-Object { 
        $_.Port -in @('80', '443', '8080', '8443') -or 
        $_.Service -eq 'http' -or 
        $_.Service -like '*ssl*' -or 
        $_.Version -like '*Web*' -or 
        $_.Version -like '*web*'
    } | ForEach-Object {
        if ($_.Port -in @('443', '8443') -or $_.Service -like '*ssl*') {
            "https://$($_.Host):$($_.Port)/"
        } else {
            "http://$($_.Host):$($_.Port)/"
        }
    }
    $webHosts | Sort-Object -Unique | Set-Content (Join-Path $outpath "web.txt")
    Write-Host "  - web.txt"
}

function Invoke-Ssl {
    $csvContent = Import-Csv (Join-Path $outpath "parsed_nmap.csv")
    $sslHosts = $csvContent | Where-Object { 
        $_.Port -eq '443' -or 
        $_.Service -like '*ssl*' -or 
        $_.Service -like '*tls*' -or 
        $_.Version -like '*ssl*' -or 
        $_.Version -like '*tls*'
    } | ForEach-Object { "$($_.Host):$($_.Port)" }
    $sslHosts | Sort-Object -Unique | Set-Content (Join-Path $outpath "ssl.txt")
    Write-Host "  - ssl.txt"
}

function Invoke-Ssh {
    $csvContent = Import-Csv (Join-Path $outpath "parsed_nmap.csv")
    $sshHosts = $csvContent | Where-Object { 
        $_.Port -eq '22' -or 
        $_.Service -like '*ssh*' -or 
        $_.Version -like '*ssh*'
    } | ForEach-Object { "$($_.Host):$($_.Port)" }
    $sshHosts | Sort-Object -Unique | Set-Content (Join-Path $outpath "ssh.txt")
    Write-Host "  - ssh.txt"
}

function Invoke-HostPorts {
    $csvContent = Import-Csv (Join-Path $outpath "parsed_nmap.csv")
    $hostPortsPath = Join-Path $outpath "hosts"
    New-Item -ItemType Directory -Force -Path $hostPortsPath | Out-Null

    $csvContent | Group-Object { "$($_.Protocol)_$($_.Port)-$($_.Service)" } | ForEach-Object {
        $fileName = "$($_.Name).txt"
        $_.Group.Host | Sort-Object -Unique | Set-Content (Join-Path $hostPortsPath $fileName)
    }
    Write-Host "  - hosts/[PROTOCOL]_[PORT]-[SERVICE].txt"
}

function Invoke-ClosedSummary {
    $closedPorts = Get-Content $inputfilepath | Where-Object { $_ -match '/closed/' } | ForEach-Object {
        $endpoint = ($_ -split ' ')[1]
        $ports = ($_ -split ' ')[3..$_.Length] -join ' ' -split ',' | Where-Object { $_ -match '/closed/' } | ForEach-Object { ($_ -split '/')[0].Trim() }
        [PSCustomObject]@{
            Host = $endpoint
            ClosedPorts = $ports
        }
    }

    $closedSummary = $closedPorts | Group-Object Host | ForEach-Object {
        "Closed Ports For Host: $($_.Name)`n       $($_.Group.ClosedPorts -join ', ')`n"
    }

    $closedSummary | Set-Content (Join-Path $outpath "closed-summary.txt")
    Write-Host "  - closed-summary.txt"
}

function Invoke-Report1 {
    $openPorts = Get-Content $inputfilepath | Where-Object { $_ -match '/open/' } | ForEach-Object {
        $endpoint = ($_ -split ' ')[1]
        $ports = ($_ -split ' ')[3..$_.Length] -join ' ' -split ',' | Where-Object { $_ -match '/open/' } | ForEach-Object { ($_ -split '/')[0].Trim() }
        [PSCustomObject]@{
            Host = $endpoint
            OpenPorts = $ports
        }
    }

    $report = $openPorts | Group-Object Host | ForEach-Object {
        "$($_.Name) [$($_.Group.OpenPorts -join ', ')]"
    }

    $report | Sort-Object | Set-Content (Join-Path $outpath "report1.txt")
    Write-Host "  - report1.txt"
}

# "Roll It"
Invoke-NmapParse