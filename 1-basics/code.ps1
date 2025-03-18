# Search PowerShell logs for event type 4104 (script block logs) and furthermore look for messages that contain the word "encoded" (base 64 conversion), then print each of those messages out
Get-WinEvent -LogName 'PowerShellCore\Operational' | ? {$_.id -eq 4104} | ? {$_.message -like "*-encoded*"} | %{$_.message}

# This is another way to achieve the same thing
Get-WinEvent -LogName PowerShellCore/Operational | Select-Object -Property message,id |  | Where-Object {$_.message -match "-encoded." -and $_.id -eq "4104"} | Format-Table -wrap 