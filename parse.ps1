$logon = Get-Content ./logins.json | ConvertFrom-Json

for ($i = 0; $i -lt $logon.Count; $i++) {
    
    if($logon[$i].EventId -eq 4624){
        $val = $logon | Where-Object {
            (get-date -Date $_.TimeCreated) -gt (get-date -date $logon[$i].TimeCreated) -and
            $_.PayloadData3 -eq  $logon[$i].PayloadData3
        }
        for ($j = 0; $j -lt $val.Count; $j++) {
            
            if ($val[$j].EventId -eq 4634){
                
                $UtcTime = Get-Date -Date "2021-03-16 12:03:21Z"
                $Start = Get-Date -Date $logon[$i].TimeCreated 
                $End = Get-Date -Date $val[$j].TimeCreated
                
                if($UtcTime -gt $start -and $UtcTime -lt $end ){
                    write-host($UTCTime)
                    write-host($Start)
                    write-host($End)
                    Write-Host("look at " + $logon[$i].PayloadData3)
                }
            }
        }
    }   
}