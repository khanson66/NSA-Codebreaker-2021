
foreach($file in Get-ChildItem '.\hold'){
    $unames = Get-Content -Path $file
    ForEach-Object -InputObject $unames -Parallel {
        $name = $_ 
        python.exe C:\Users\kyle\Desktop\breakers\decryption\key.py $name
    
    } -ThrottleLimit 500
    write-host $file.Name
}

