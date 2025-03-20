########################################################

Get-Process | Select-Object -Property ProcessName,Id,Path

########################################################

Get-Process | Select-Object -Property name,path | Where-Object { $_.name -eq "svchost" -and $_.path -ne "C:\Windows\System32*"}

########################################################

Get-CimInstance Win32_Service | Select-Object -Property Name,Description

########################################################

cat C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1

########################################################

Get-NetTCPConnection

Get-NetTCPConnection | Select-Object -Property LocalPort, OwningProcess | Where-Object -Property LocalPort -eq 8080

Get-Process | Where-Object -Property Id -eq 3912

########################################################

Get-CimInstance Win32_Service | Select-Object -Property * | Where-Object -Property Name -eq 'Daggoth'

########################################################

Get-Process | Where-Object -Property ProcessName -eq Evolution_Complete | Select-Object -Property Id

Get-Process | Where-Object -Property ProcessName -eq My_Life_For_Aiur | Select-Object -Property Id

Get-Process | Where-Object -Property ProcessName -eq Daggoth | Select-Object -Property Id

$id1 = 1111
$id2 = 2222
$id3 = 3333

Get-NetTCPConnection | Where-Object OwningProcess -eq $id1 | Select-Object -Property LocalPort

Get-NetTCPConnection | Where-Object OwningProcess -eq $id2 Select-Object -Property LocalPort

Get-NetTCPConnection | Where-Object OwningProcess -eq $id3 | Select-Object -Property LocalPort

########################################################

# To transfer a file from one machine to another:
# On the host you want to transfer a file TO by PULLING it:
scp student@<target-host-ip:C:\Users\Administrator\Desktop\DebuggerPE.ps1> .

# If you want to copy from LOCAL and PUSH to REMOTE:
scp .\DebuggerPE.ps1 student@<target-host-ip:C:\Users\Administrator\Desktop\DebuggerPE.ps1> .