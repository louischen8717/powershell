# ===============================
# Process all TXT files under current directoy (nmap scan result)
# Output result to the CSV files with the same name
# Input TXT files: .\*.txt
# Output CSV file: .\*csv
# Command: nmap -sU -sS --script smb-enum-shares --script-args 
#  smbusername=admin,smbpassword= -p U:137,U:138,T:139,T:445 <IP>
# System Requirement: Get-ExecutionPolicy
# Set-ExecutionPolicy remotesigned
# Set-ExecutionPolicy unrestricted  ( if remotesigned not working )
# ===============================
$filenames = Get-ChildItem -Path "." | Where-Object {$_.Extension -eq ".txt"} | Select-Object Name
foreach ($f in $filenames){ 
  $fp = ".\" + $f.name
  $ofp = $fp.Replace(".txt",".csv")
  Write-Host $fp
  Write-Host $ofp
  $headline = "Hostname,IPaddress,smbID,ShareName,ShareRight"
  Write-Output $initstring | Out-File $ofp
  
  $headline = "Hostname,IPaddress,139/tcp,445/tcp,137/udp,138/udp,smbID,SN-1,SR-1,SN-2,SR-2,SN-3,SR-3,SN-4,SR-4,SN-5,SR-5"
  # Output Headline to CSV file
  Write-Output $headline | Out-File ".\$ofp"
  
  # Read file, splict by host
  $nmapscan = (Get-Content -Raw $fp) -split 'Nmap scan report for '
  
  # Each host result split by 'Nmap scan report for '
  for ($i = 1; $i -le ($nmapscan.length - 1); $i += 1) {
  # Extract Port status
    $tcp139 = ($nmapscan[$i] -split '139/tcp ')[1].split()[0]
    Write-host "139/tcp: $tcp139"
    $tcp445 = ($nmapscan[$i] -split '445/tcp ')[1].split()[0]
    Write-host "445/tcp: $tcp445"
    $udp137 = ($nmapscan[$i] -split '137/udp ')[1].split()[0]
    Write-host "137/udp: $udp137"
    $udp138 = ($nmapscan[$i] -split '138/udp ')[1].split()[0]
    Write-host "138/udp: $udp138"
  # Extract FQDN
  # Extract IPaddr
    write-host $nmapscan[$i].split().Trim()[0]
    write-host $nmapscan[$i].split().Trim()[1]
  # FQDN found:
    if ( $nmapscan[$i].split().Trim()[1] -ne '' ){
      $fqdn = $nmapscan[$i].split().Trim()[0]
  # Remove "( )"
      $ipaddr = $nmapscan[$i].split()[1].replace("`(","").replace("`)","")
      write-host "FQDN: $fqdn"
      Write-host "IP: $ipaddr`n"
      $hostname = $fqdn.split('.')[0]
      $outcsv = "$hostname,$ipaddr,$tcp139,$tcp445,$udp137,$udp138" 
    } else {
  # FQDN not found:
      $ipaddr = $nmapscan[$i].split().Trim()[0]
      write-host "IP: $ipaddr`n"
      $outcsv = ",$ipaddr,$tcp139,$tcp445,$udp137,$udp138" }
      
  # SMB Share Information existed
    if ($nmapscan[$i] -match "Host script results:") {
    # Extract smbID: <blank>/guest | smbusername
      $smbid = ($nmapscan[$i] -split 'account_used: ')[1].split()[0]
      if ($smbid -eq "<blank>") { 
        $smbid = 'Anonymous'
        Write-host $smbid
      # Only one line for Anonymous account -> add to line
        $outcsv = "$outcsv,'Anonymous'"
      # For each share split by \\IPaddr\:  
        $si = $nmapscan[$i] -split "\\\\$ipaddr\\"
        for ($j = 1; $j -le ($si.length - 1); $j += 1) {
          $sn = $si[$j].split(':')[0]
          Write-Host $sn
         # Sharename -> add to line
          $outcsv = "$outcsv,$sn"
          $sr = ($si[$j] -split 'Anonymous access: ')[1].split()[0]
          Write-Host $sr
         # Shareright -> add to line
          $outcsv = "$outcsv,$sr"
        }
      } else {
      # Two lines, one for Anonymous, one for smbnameuser
        Write-host $smbid
        $outcsva = "$outcsv,Anonymous"
        $outcsvs = "$outcsv,$smbid"
      # For each share split by \\IPaddr\:  
        $si = $nmapscan[$i] -split "\\\\$ipaddr\\"
        for ($j = 1; $j -le ($si.length - 1); $j += 1) {
          $sn = $si[$j].split(':')[0]
          Write-Host $sn
         # Sharename -> add to line
          $outcsva = "$outcsva,$sn"
          $outcsvs = "$outcsvs,$sn"
          $sra = ($si[$j] -split 'Anonymous access: ')[1].split()[0]
          $srs = ($si[$j] -split 'Current user access: ')[1].split()[0]
          Write-Host "Anonymous : $sra"
          Write-Host "$smbid : $srs"
         # Shareright -> add to line
          $outcsva = "$outcsva,$sra"
          $outcsvs = "$outcsvs,$srs"
          $outcsv = "$outcsva`n$outcsvs"
        }
      }
    }
    Write-host "`n*** $outcsv`n"
    Write-Output $outcsv | Out-File ".\$ofp" -append
  }
}