# Regex for valid IPV4 address:
$pattern = '^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'

########################################################

# Getting Network and Processes (Function using a PSCustomObject)
function PNN{
    Get-NetTCPConnection | ForEach-Object {
        $connection = $_
        $processId = $connection.OwningProcess
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($process) {
                [PSCustomObject]@{
                    LocalAddress = $connection.LocalAddress
                    LocalPort = $connection.LocalPort
                    RemoteAddress = $connection.RemoteAddress
                    RemotePort = $connection.RemotePort
                    State = $connection.State
                    ProcessId = $processId
                    ProcessName = $process.ProcessName
                    ProcessPath = $process.Path
            }
        }
    } | Where-Object -Property State -eq "Listen" | select -last 5 | Format-Table -AutoSize
}

# PS C:\> PNN
# LocalAddress  LocalPort RemoteAddress RemotePort  State ProcessId ProcessName  ProcessPath
# ------------  --------- ------------- ----------  ----- --------- -----------  -----------
# 0.0.0.0             902 0.0.0.0                0 Listen      4248 vmware-authd C:\Program Files (x86)\VMware\VMware Workstation\vmware-authd.exe
# 192.168.195.1       139 0.0.0.0                0 Listen         4 System
# 192.168.177.1       139 0.0.0.0                0 Listen         4 System
# 192.168.1.69        139 0.0.0.0                0 Listen         4 System
# 0.0.0.0             135 0.0.0.0                0 Listen      1084 svchost      C:\Windows\system32\svchost.exe

########################################################

# Parameters in PowerShell functions are used to make functions more flexible and reusable.

# Designing a Basic Function with Custom Parameters

function UserInfo {
    param (
        [string]$Username,
        [switch]$IncludeDetails
    )

    if ($IncludeDetails) {
        Write-Host "Getting detailed information for user $Username"
        Get-LocalUser | Where-Object {$_.Name -eq $Username} | Select-Object -Property Name, Enabled, PasswordRequired, SID

    } else {
        Write-Host "Getting basic information for user $Username"
        Get-LocalUser | Where-object {$_.Name -eq $Username} | Select-Object -Property Name, Enabled
    }
}

# PS C:\> UserInfo -Username Administrator -IncludeDetails
# Getting detailed information for user Administrator

# Name          Enabled PasswordRequired SID
# ----          ------- ---------------- ---
# Administrator   False             True S-1-5-21-3780157036-4114611373-2348294647-500

# PS C:\> UserInfo -Username Administrator
# Getting basic information for user Administrator

# Name          Enabled
# ----          -------
# Administrator   False

########################################################

# Once a suspicious process is located using Get-Process, looks at WinEvent Logs for process creation, look at the "Process Command Line" output for what the full string that's being used at process creation

Get-WinEvent -logname Security | where-object {$_.ID -eq '4688'} | Format-Table -wrap

# Found a suspicious process at:
# "powershell.exe" -Command "Start-Process 'C:\Users\Admin\AppData\Local\Evolution_Complete' -WindowStyle Hidden"
# and
# "powershell.exe" -Command "Start-Process 'C:\Users\Public\Downloads\My_Life_For_Aiur.exe' -WindowStyle Hidden"

########################################################

# Look for a Scheduled Task and output it to a table

Get-ScheduledTask | Format-Table TaskName, Description, Source | findstr /i Aiu