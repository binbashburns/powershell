# Aliases

Windows PowerShell includes aliases for certain cmdlets as well as the option for you to create custom aliases. This allows the user to create aliases to incorporate cmd or bash commands into PowerShell. It is important to know that custom aliases are deleted when the PowerShell session is ended. Aliases can be created persistently using PowerShell profiles which will be covered in a later lesson.

**Resolving Aliases.**
```
$alias:dir
Get-ChildItem

$alias:ls
Get-Alias -Name Dir
```
**List all aliases of a given cmdlet.**
```
Get-Alias -Definition Get-ChildItem
Get-Alias -Definition Get-Content
```
## Creating Aliases

There is the ability to create cmdlet aliases, as mentioned earlier.

**Creating an Alias: The Set-Alias cmdlet creates or changes an alias for a cmdlet or a command, such as a function, script, file, or other executable.**
```
Set-Alias edit notepad.exe
```
## Deleting Aliases

All new aliases are automatically removed once you exit the current PowerShell session. But they can still be deleted manually.

**Deleting Aliases.**
```
Remove-Item alias:edit
```
# Output Formatting

When you are working with large amounts of data, sometimes it is hard to find what you are looking for. Performing output formatting on the data reduces the amount of unwanted data to pinpoint what you are searching for in a more efficient manner.

## Sort-Object

   - Sort-Object sorts the data by user defined property values

**List the contents of a directory and sort the files by name, alphabetically.**
```
PS C:\> Get-ChildItem | Sort-Object
```
**Sort files by size, largest to smallest.**
```
PS C:\> Get-ChildItem | Sort-Object -Property Length -Descending
```
**Sort the output of a Get-NetTCPConnection and return the first 10 results, descending by remote IP address.**
```
PS C:\> Get-NetTCPConnection | Select-Object -Property RemoteAddress, RemotePort, State | Sort-Object -Property RemoteAddress -Descending | Select-Object -First 10
    RemoteAddress  RemotePort       State
    -------------  ----------       -----
    99.83.228.14          443 Established
    99.83.228.14          443 Established
    99.83.228.14          443 Established
    99.83.228.14          443 Established
    75.2.84.65            443 Established
    75.2.116.105          443 Established
    52.159.126.152        443 Established
    52.127.72.34          443 Established
    52.127.72.34          443 Established
    52.127.64.27          443 Established
```
## Filter Left, Sort Right

In order to maximize efficiency in your PowerShell code, always filter before sorting. This ensures that PowerShell eliminates the amount of data it has to parse before displaying the data. Below are some examples of an inefficient command and an efficient command measured by time to complete.

**Low efficiency command.**
```
PS C:\> Get-ChildItem -Path C:\Windows\System32 -Recurse -ErrorAction SilentlyContinue | Sort-Object | Select-Object -Property Name

PS C:\> Measure-Command {Get-ChildItem -Path C:\Windows\System32 -Recurse -ErrorAction SilentlyContinue | Sort-Object | Select-Object -Property Name}

    Days              : 0
    Hours             : 0
    Minutes           : 0
    Seconds           : 2
    Milliseconds      : 111
    Ticks             : 21111244
    TotalDays         : 2.44343101851852E-05
    TotalHours        : 0.000586423444444444
    TotalMinutes      : 0.0351854066666667
    TotalSeconds      : 2.1111244
    TotalMilliseconds : 2111.1244
```
**Higher efficiency command.**
```
PS C:\> Get-ChildItem -Path C:\Windows\System32 -Recurse -ErrorAction SilentlyContinue | Select-Object -Property Name | Sort-Object

PS C:\> Measure-Command {Get-ChildItem -Path C:\Windows\System32 -Recurse -ErrorAction SilentlyContinue | Select-Object -Property Name | Sort-Object}

    Days              : 0
    Hours             : 0
    Minutes           : 0
    Seconds           : 1
    Milliseconds      : 37
    Ticks             : 10370187
    TotalDays         : 1.200253125E-05
    TotalHours        : 0.00028806075
    TotalMinutes      : 0.017283645
    TotalSeconds      : 1.0370187
    TotalMilliseconds : 1037.0187
```
The performance difference seems minor in the above examples. However, when working with commands that gather data from multiple machines, or over the network, the difference in efficiency could be a significant factor in time to complete.

Select-Object

   - Sometimes you may want to display only specific object properties. This may cut down on data that is displayed and help you find a needle in the haystack. You can do this with Select-Object.

       - This command is like the Linux awk command whereas you can display columns of data

       - This command also has Linux head/tail functionality

       - This command requires you to pipe data to it

       - Properties that will be displayed are comma separated

   - This command also allows column headers to be stripped off data.

       - Use the -ExpandProperty Parameter

**Display properties of the Get-Process command, also demonstrates similarities with Linux head and tail commands.**
```
PS C:\> Get-Process | Select-Object -Property Name, ID -First 5
    Name                         Id
    ----                         --
    AcrobatNotificationClient 15892
    acrotray                  17964
    AdobeCollabSync            8396
    AdobeCollabSync           15752
    AdobeNotificationClient    3860

PS C:\> Get-Process | Select-Object -Property Name, ID -Last 5
    Name                      Id
    ----                      --
    wininit                  836
    winlogon                1204
    WINWORD                14884
    WMIRegistrationService  4148
    WUDFHost                 904
```
**Use -ExpandProperty to remove the column header.**
```
PS C:\> Get-Process | Select-Object -ExpandProperty Name -First 5
    AcrobatNotificationClient
    acrotray
    AdobeCollabSync
    AdobeCollabSync
    AdobeNotificationClient

PS C:\> Get-Process | Select-Object -ExpandProperty Name -Last 5
    wininit
    winlogon
    WINWORD
    WMIRegistrationService
    WUDFHost
```
## Where-Object

   - PowerShell can filter data based on very specific criteria. To do this, use the Where-Object command

       - Where-Object requires data be piped to it

       - Where-Object statements can be written with and without the scriptblock { }

       - Using the scriptblock allows the user to have multiple conditions

       - Can be used with the `$_` special PowerShell pipeline current object variable

**Where-Object with a single condition with and without the $_ special pipeline variable.**
```
PS C:\> Get-Service | Where-Object { $_.Status -eq 'running' } | Select-Object -First 5
    Status   Name               DisplayName
    ------   ----               -----------
    Running  AdobeARMservice    Adobe Acrobat Update Service
    Running  AdobeUpdateService AdobeUpdateService
    Running  Appinfo            Application Information
    Running  AppXSvc            AppX Deployment Service (AppXSVC)
    Running  AudioEndpointBuil… Windows Audio Endpoint Builder

PS C:\> Get-Service | Where-Object Status -eq 'running'| Select-Object -Last 5
    Status   Name               DisplayName
    ------   ----               -----------
    Running  WpnService         Windows Push Notifications System Ser…
    Running  WpnUserService_e9… Windows Push Notifications User Servi…
    Running  wscsvc             Security Center
    Running  WSearch            Windows Search
    Running  wuauserv           Windows Update
```
**Where-Object with multiple conditions using the $_ special pipeline variable.**
```
PS C:\> Get-Service | Where-Object { $_.Status -eq 'running' -and $_.name -like 'WIN*'}
    Status   Name               DisplayName
    ------   ----               -----------
    Running  WinDefend          Microsoft Defender Antivirus Service
    Running  WinHttpAutoProxyS… WinHTTP Web Proxy Auto-Discovery Serv…
    Running  Winmgmt            Windows Management Instrumentation
```
## Group-Object

   - It may be helpful to gather files into groups to better track if large numbers of files have been added or removed.

   - Use the Group-Object command to group objects.

**Note**

Malware could be introduced or dropped into the C:\Windows\System32 directory due to the large number of .dll files located there. The Group-Object command can help group the files into manageable groups and help you keep track of or baseline the files in this directory.

**Group files by extension and sort them by count, descending.**
```
PS C:\> Get-ChildItem -Path C:\Windows\System32 | Group-Object -Property Extension | Sort-Object -Property Count -Descending | Select-Object -First 5
    Count Name                      Group
    ----- ----                      -----
    3733 .dll                      {C:\Windows\System32\69fe178f-26e7-43a9-aa7d-2b616b672dde_eventlogservice.dll, C:\Wind…
    673 .exe                      {C:\Windows\System32\agentactivationruntimestarter.exe, C:\Windows\System32\AgentServi…
    147                           {C:\Windows\System32\0409, C:\Windows\System32\AdvancedInstallers, C:\Windows\System32…
    120 .NLS                      {C:\Windows\System32\C_037.NLS, C:\Windows\System32\C_10000.NLS, C:\Windows\System32\C…
    80 .png                      {C:\Windows\System32\@AdvancedKeySettingsNotification.png, C:\Windows\System32\@AppHel…
```
# Script Constructs (Conditional Loops and Switches)

Think of a condition as a question with the answer being either positive (true) or negative (false). Nearly all questions are phrased with comparisons in PowerShell.

## If/Elseif/Else

Where-Object is insufficient when longer code segments are needed. Once the condition is met, the ***If statement*** terminates. You can use an If/Elseif/Else statement to make decisions. You can also use it to evaluate data that you have queried or user input.

**Standard If/Elseif/Else Syntax.**
```
If (condition) {
    # Code to be executed if condition applies
} Elseif (different condition) {
    # Code to be executed if different condition applies
} Else {
    # Code to be executed if none of the conditions apply
}
```
**if/elseif/else statement to determine which address range an IP address falls within.**
```
PS C:\>
$ipAddressString = "172.64.0.100"
$ipAddress = [System.Net.IPAddress]::Parse($ipAddressString)

if ($ipAddress.AddressFamily -eq 'InterNetwork' -and (
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("10.0.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("10.255.255.255").IPAddressToString) -or
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("172.16.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("172.31.255.255").IPAddressToString) -or
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("192.168.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("192.168.255.255").IPAddressToString)))
{
    Write-Output "The IP $ipAddressString is in the private IP address space."
} elseif ($ipAddress.AddressFamily -eq 'InterNetwork' -and (
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("0.0.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("9.255.255.255").IPAddressToString) -or
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("11.0.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("172.15.255.255").IPAddressToString) -or
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("172.32.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("192.167.255.255").IPAddressToString) -or
    ($ipAddress.IPAddressToString -ge [System.Net.IPAddress]::Parse("192.169.0.0").IPAddressToString -and $ipAddress.IPAddressToString -le [System.Net.IPAddress]::Parse("255.255.255.255").IPAddressToString)))
{
    Write-Output "The IP $ipAddressString is in the public IP address space."
} else {
    Write-Output "$ipAddressString is an Invalid IP address."
}

    The IP 172.64.0.100 is in the public IP address space.
```


**Note**

Since the .NET framework is used to parse IP Addresses, the above if/elseif/else statement will error out if an invalid IP address is stored in the variable. This can be solved using error handling, which will be covered in a lesson on Day 4.

**If Statement using a stored variable from a PSDrive.**
```
PS C:\> $FreeSpace = (Get-PSDrive -PSProvider FileSystem | Select-Object -Property @{Name='GBFree'; Expression={[math]::Round($_.Free / 1GB, 2)}} -First 1).GBFree

PS C:\> if ($FreeSpace -lt 250) {
            Write-Host "You have less than 250GB of disk space available"
        }
```
**If Else using a stored variable from a PSDrive.**
```
PS C:\> $FreeSpace = (Get-PSDrive -PSProvider FileSystem | Select-Object -Property @{Name='GBFree'; Expression={[math]::Round($_.Free / 1GB, 2)}} -First 1).GBFree

PS C:\> if($FreeSpace -gt 250) {
            Write-Host "You have more than 250GB of disk space available"
        } else {
            Write-Host "You have less than 250GB of disk space available"
        }
```
**If Elseif Else using a user stored custom variable and multiple elseif conditions.**
```
PS C:\> $FreeSpace = .5
PS C:\> if($FreeSpace -gt 250) {
            Write-Host "You have more than 250GB of disk space available"
        } elseif (($FreeSpace -gt 100) -and ($FreeSpace -lt 250)){
            Write-Host "You have more than 100GB of disk space, but less then 250GB available"
        } elseif (($FreeSpace -lt 100) -and ($FreeSpace -gt 1)){
            Write-Host "You have less than 100GB of disk space available"
        } elseif ($FreeSpace -lt 1) {
            Write-Host "Get a new hard drive!"
        } else {
            Write-Host "You have less than 250GB of disk space available"
        }

    Get a new hard drive!
```
## Switch

The Switch construct evaluates a single variable or item against multiple values and has a script block for each value. The script block for each value is run if that value matches the variable.

**Simple Switch Syntax.**
```
PS C:\> Switch (3) {
            1 { Write-Host "You selected menu item 1" }
            2 { Write-Host "You selected menu item 2" }
            3 { Write-Host "You selected menu item 3" }
            Default { Write-Host "You did not select a valid option" }
        }

    You selected menu item 3
```
**Switch using the -WildCard parameter for pattern matching.**
```
PS C:\> $ip = '172.64.0.100'

PS C:\> Switch -WildCard ($ip) {
            "192.168.*" { Write-Host "This computer is on the internal local area network" }
            "10.15.*" { Write-Host "This computer is in the Branch network" }
            "172.64.*" { Write-Host "This computer is in the DMZ network" }
            Default { Write-Host "This computer is not on the network" }
        }

    This computer is in the DMZ network
```
**Switch using the Default value.**
```
PS C:\> $ip = '8.8.8.8'

PS C:\> Switch -WildCard ($ip) {
            "192.168.*" { Write-Host "This computer is on the internal local area network" }
            "10.15.*" { Write-Host "This computer is in the Branch network" }
            "172.64.*" { Write-Host "This computer is in the DMZ network" }
            Default { Write-Host "This computer is not on the network" }
        }

    This computer is not on the network
```
**Switch using all values with an array.** 
```
PS C:\> $ipArray = @('172.64.0.100', '10.50.35.169','10.15.0.100','22.25.55.255')

PS C:\> $ipArray | ForEach-Object {
            $ip = $_
            $index = $ipArray.IndexOf($ip)

            switch -Wildcard ($ip) {
                "192.168.*" { Write-Host ("$ip is on the internal local area network") }
                "10.15.*" { Write-Host ("$ip is in the Branch network") }
                "172.64.*" { Write-Host ("$ip is in the DMZ network") }
                Default { Write-Host ("$ip is not on the network") }
            }
        }

    172.64.0.100 is in the DMZ network
    10.50.35.169 is on the internal local area network
    10.15.0.100 is in the Branch network
    22.25.55.255 is not on the network
```

**Important**

An **If statement** terminates after the first condition is met. A **Switch statement** is used if there are multiple comparison values that meet the condition.

## While Loop

   - The while statement (also known as a while loop) is a language construct for creating a loop that runs commands in a script block as long as a conditional test evaluates to true.

**While syntax.**
```
while (<condition>){<statement list>}
```
While Loop used to check running processes every 5 seconds for the msedge process.
```
PS C:\> $processToMonitor = "msedge"
        while ($true) {
            if (Get-Process -Name $processToMonitor -ErrorAction SilentlyContinue) {
                Write-Host "Warning: $processToMonitor is running! Possible security threat."
            }
            Start-Sleep -Seconds 5
        }

PS C:\> .\WhileLoopDemo.ps1
    Warning: msedge is running! Possible security threat.
    Warning: msedge is running! Possible security threat.
    Warning: msedge is running! Possible security threat.
    Warning: msedge is running! Possible security threat.
```
## Do While

   - The Do/While statement runs through a collection of information based on whether or not the condition evaluates to $true. This type of loop is different from the while loop because it will run at least once.

**Syntax.**
```
do {
    code block
}while(condition)
```
**Do..While Loop used to check running processes every 5 seconds for the iexplore process.** 
```
PS C:\> $processToMonitor = "iexplore"
        Write-Host "Checking if Internet Explorer is running on this host every 5 seconds..."
        Do {
            if(Get-Process -Name $processToMonitor -ErrorAction SilentlyContinue) {
                Write-Host "Warning: $processToMonitor is running! Don't use Internet Explorer!"
                Start-Sleep -Seconds 5
            }
        } While ($true)

PS C:\> .\DoWhileLoopDemo.ps1
    Checking if Internet Explorer is running on this host every 5 seconds...
    Warning: iexplore is running! Don't use Internet Explorer!
    Warning: iexplore is running! Don't use Internet Explorer!
    Warning: iexplore is running! Don't use Internet Explorer!
    Warning: iexplore is running! Don't use Internet Explorer!
```
## Do Until

   - Using Do/Until, PowerShell continues to execute the code statement until the condition evaluates to **$false**.

**Syntax.**
```
do {
    code block
}until(condition)
```
**Do..Until Loop that will continuously monitor a potential malicious process and gather details about it until it is no longer running.** 
```
PS C:\> Write-Host "Monitoring Microsoft Edge process every 60 seconds." `n
        $FilePath = (Get-CimInstance Win32_Process | Select-Object -Property Name, ProcessID, ParentProcessID, Path | Where-Object {$_.Name -eq "msedge.exe"}).Path
        $processToMonitor = "msedge"
        do {
            $isProcessRunning = Get-Process -Name $processToMonitor

            if ($isProcessRunning) {
                Write-Host "Warning: $processToMonitor is running, performing analysis on the process." `n
                Write-Host "-------------Gathering Process Information...--------------"
                Start-Sleep -Seconds 3
                Write-Output (Get-CimInstance Win32_Process | Select-Object -Property Name, ProcessID, ParentProcessID, Path | Where-Object {$_.Name -eq "msedge.exe"} | Format-Table)

                Write-Host "-------------Gathering Process Filehash...--------------"
                Start-Sleep -Seconds 3
                $FileHash = (Get-FileHash -Algorithm SHA256 -Path $FilePath | Format-Table)
                Write-Output $FileHash

                Write-Host "-------------Gathering Network Information...--------------"
                Start-Sleep -Seconds 3
                $ProcessIDs = (Get-Process | Select-Object -Property Name, ID | Where-Object {$_.Name -eq "msedge"}).Id
                $Network = foreach ($ID in $ProcessIDs) {
                    Get-NetTCPConnection | Select-Object -Property LocalAddress, RemoteAddress, RemotePort, OwningProcess, State | Where-Object { $_.OwningProcess -eq $ID -and $_.State -ne "Bound" }
                }
                Write-Output $Network | Format-Table
            }
            Start-Sleep -Seconds 60
        } until (-not $isProcessRunning)

    Warning: msedge is running, performing analysis on the process.

    -------------Gathering Process Information...--------------

    Name       ProcessID ParentProcessID Path
    ----       --------- --------------- ----
    msedge.exe      8416            8808 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      8448            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      5468            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      4372            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      8272            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      5664            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      1696            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    msedge.exe      5168            8416 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe

    -------------Gathering Process Filehash...--------------

    Algorithm Hash                                                             Path
    --------- ----                                                             ----
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    SHA256    065D2802A5069ABAF7C12EE356620643A121F72ACE223D505C32EE525F9B91D3 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe

    -------------Gathering Network Information...--------------

    LocalAddress RemoteAddress  RemotePort OwningProcess       State
    ------------ -------------  ---------- -------------       -----
    10.50.33.11  169.150.236.98        443          2088 Established
    10.50.33.11  185.152.66.243        443          2088 Established
    10.50.33.11  172.66.40.149         443          2088 Established
    10.50.33.11  151.101.17.188        443          2088 Established
    10.50.33.11  185.152.66.243        443          2088 Established
    10.50.33.11  20.42.73.28           443          2088 Established
    10.50.33.11  23.207.53.173         443          2088 Established
```
## Foreach

The Foreach Loop is very similar to a For Loop in other languages. In PowerShell you can use the Foreach Loop to iterate through a collection of objects and pull information ***Foreach*** of the objects in the collection.

**Syntax.**
```
$items = "objects"
Foreach ($item in $items){
    <Code to be executed>
}
```
**Foreach Loop that iterates through each user on the host and displays if any administrator accounts are enabled.**
```
PS C:\> $Users = Get-LocalUser
        Foreach ($User in $Users){
            if ($User.Name -eq "Admin" -or $User.Name -eq "Administrator"){
                Write-Host ""$User.Name" is enabled:"$User.Enabled""
            }
        }

    Admin  is enabled: True
    Administrator  is enabled: True
```
## ForEach-Object

The `ForEach-Object` cmdlet performs an operation on each item in a collection of input objects. The input objects can be piped to the cmdlet or specified using the InputObject parameter. [Microsoft Docs: ForEach-Object](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/foreach-object?view=powershell-7.3)

**Syntax.**
```
PS C:\> $Objects = "Value"
        $Objects | Foreach-Object {<Code to be executed>}
```
**Foreach-Object construct that performs an action on the objects in the pipeline and displays if any administrator accounts are enabled.**
```
PS C:\> $Users = Get-LocalUser
        $Users | ForEach-Object {
            if ($_.Name -ieq 'Admin' -or $_.Name -ieq 'Administrator'){
                Write-Host ""$_.Name" is enabled:"$_.Enabled""
            }
        }

    Admin  is enabled: True
    Administrator  is enabled: True
```
**Display file sizes.**
```
Get-ChildItem | ForEach-Object { $_.Length / 1KB }
```
***Foreach*** and ***ForEach-Object*** are very similar with the main difference being that ***ForEach-Object*** obtains its values from a pipeline while ***ForEach*** is used to iterate over a collection of objects. Another difference is that ***ForEach*** can only process objects that are completely available while ***ForEach-Object*** processes each result one at a time, so you get results in real-time. For example, if you were going to use the following:
```
ForEach ($item in gci C:\ -recurse){$item.name}
```
This command would take a long time because ***ForEach*** can’t process objects until ***Get-ChildItem*** is completely finished listing the directory. If you were to do the following:
```
Get-ChildItem C:\ -recurse | ForEach-Object{$_.name}
```
Then you would get the results one at a time in real-time as ***Get-ChildItem*** is processing them.

**Note**

There are several use-cases for both ForEach and Foreach-Object, it is important to know which one is better depending on the scenario.

## Windows Management Instrumentation (WMI) and Common Information Model (CIM)

WMI and CIM are related technologies, both of which are based on industry standards. WMI is an older technology based on proprietary technology. CIM is a newer technology that is based on open, cross-platform standards.

You can learn more about WMI and CIM at [this link](https://learn.microsoft.com/en-us/training/modules/review-common-information-model-windows-management-instrumentation/1-introduction)

**Important**

CIM commands use WS-MAN to establish remote connections. WMI uses DCOM which might require special firewall exceptions due to the way it randomly chooses ports to which it connects.

**Note**

Microsoft considers WMI within Windows PowerShell to be deprecated and recommends using CIM commands instead.

On previous days, CIM commands were demonstrated on multiple occasions to pull specific information about a process such as the ***Parent Process ID***. It is important to understand and learn CIM commands as they provide valuable information that cannot be gained using standard PowerShell Cmdlets.

**Searching CIM repository for a desired command and running some commands using CIM Classes**
```
PS C:\> Get-CimClass -Namespace root\CIMv2 | Select-String "network"
    ROOT/CIMv2:CIM_NetworkAdapter
    ROOT/CIMv2:Win32_NetworkAdapter
    ROOT/CIMv2:Win32_NetworkConnection
    ROOT/CIMv2:Win32_NetworkProtocol
    ROOT/CIMv2:Win32_NetworkClient
    ROOT/CIMv2:Win32_SystemNetworkConnections
    ROOT/CIMv2:Win32_NetworkAdapterSetting
    ROOT/CIMv2:Win32_NetworkAdapterConfiguration

PS C:\> Get-CimInstance Win32_NetworkAdapterConfiguration | Select-Object -Property DNSHostName,InterfaceIndex,IPAddress,IPSubnet | Format-List
    DNSHostName    :
    InterfaceIndex : 6
    IPAddress      :
    IPSubnet       :

    DNSHostName    : DESKTOP-DC1NSGJ
    InterfaceIndex : 5
    IPAddress      : {10.50.33.11, fe80::3326:f9c3:a42b:6fed}
    IPSubnet       : {255.255.0.0, 64}

PS C:\> Get-Ciminstance Win32_Process | Select-Object -Property Name,ProcessID,ParentProcessID | Where-Object -Property Name -eq 'pwsh.exe'
    Name     ProcessID ParentProcessID
    ----     --------- ---------------
    pwsh.exe      4316             492

PS C:\> Get-CimInstance Win32_Service | Select-Object -Property * | Where-Object -Property Name -eq 'Spooler'

    Name                    : Spooler
    Status                  : OK
    ExitCode                : 0
    DesktopInteract         : True
    ErrorControl            : Normal
    PathName                : C:\WINDOWS\System32\spoolsv.exe
    ServiceType             : Own Process
    StartMode               : Auto
    Caption                 : Print Spooler
    Description             : This service spools print jobs and handles interaction with the printer.  If you turn off this service, you won’t be able to print or see your printers.
    InstallDate             :
    CreationClassName       : Win32_Service
    Started                 : True
    SystemCreationClassName : Win32_ComputerSystem
    SystemName              : POWERSHELL-PE
    AcceptPause             : False
    AcceptStop              : True
    DisplayName             : Print Spooler
    ServiceSpecificExitCode : 0
    StartName               : LocalSystem
    State                   : Running
    TagId                   : 0
    CheckPoint              : 0
    DelayedAutoStart        : False
    ProcessId               : 2628
    WaitHint                : 0
    PSComputerName          :
    CimClass                : root/cimv2:Win32_Service
    CimInstanceProperties   : {Caption, Description, InstallDate, Name…}
    CimSystemProperties     : Microsoft.Management.Infrastructure.CimSystemProperties
```
A valuable resource for learning CIM commands can be found at [this link](https://learn.microsoft.com/en-us/training/modules/query-configuration-information/2-list-local-repository-namespaces-classes)

## Just Enough Administration (JEA)

JEA is a way we can reduce the attack surface created by PSRemoting being allowed on a network. JEA provides Windows Server and Windows client operating systems with Role Based Access Control (RBAC) functionality built upon PSRemoting.

JEA uses a special, privileged, virtual account rather than a standard user account. This has several benefits: the user’s credentials are not stored on the remote host, the user account that is used to connect to the endpoint doesn’t need to be privileged, the virtual account is limited to the system on which it is hosted, and it has local administrator privileges but is limited to performing only activities defined by JEA.

**Note**

Microsoft states that configuring JEA can be a complicated process. The Administrator configuring it should be very familiar with any PowerShell cmdlets, parameters, aliases, and values needed to perform administrative tasks.

You can learn more about JEA, including ways to configure it [here](https://learn.microsoft.com/en-us/training/modules/just-enough-administration-windows-server/)

## Invoke-Command

Using the Invoke-Command cmdlet, you can remotely pull information from another computer using WSMan and WinRM. This is an alternative to entering a remote session on the computer and allows the user to easily save results to output files for later analysis.

**Note**

If running Invoke-Command on a computer that is not joined to a domain, you will have to use runas in order to authenticate to a remote domain joined computer. You will also require credentials for the target remote host. It is outside the scope of the course, but you can learn more about runas commands here https://www.jamesserra.com/archive/2011/08/how-to-run-programs-as-a-domain-user-from-a-non-domain-computer/

**Using Invoke-Command to pull valuable information from a remote host and storing it locally.** 
```
# Query the remote host for the desired information, testing with standard output
PS C:\Users\student\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {Get-Process | Select-Object -Property Name,ID,Path | Where-Object {$_.Path -like "C:\Windows\System32\*"}} | Select-Object -First 5

    Name           : AggregatorHost
    Id             : 3956
    Path           : C:\Windows\System32\AggregatorHost.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 6e28f7ed-1ab9-4263-ab09-0494bab6bcf6

    Name           : conhost
    Id             : 7156
    Path           : C:\Windows\system32\conhost.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 6e28f7ed-1ab9-4263-ab09-0494bab6bcf6

    Name           : ctfmon
    Id             : 1684
    Path           : C:\Windows\system32\ctfmon.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 6e28f7ed-1ab9-4263-ab09-0494bab6bcf6

    Name           : dfsrs
    Id             : 3208
    Path           : C:\Windows\system32\DFSRs.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 6e28f7ed-1ab9-4263-ab09-0494bab6bcf6

    Name           : dfssvc
    Id             : 3500
    Path           : C:\Windows\system32\dfssvc.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 6e28f7ed-1ab9-4263-ab09-0494bab6bcf6

# Query the remote host for the same information, but store it locally for analysis
PS C:\Users\student\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {Get-Process | Select-Object -Property Name,ID,Path | Where-Object {$_.Path -like "C:\Windows\System32\*"} | Select-Object -First 10} | Out-File -FilePath C:\Users\student\Desktop\DomainControllerProcesses.txt

PS C:\Users\student\Desktop> Get-Content .\DomainControllerProcesses.txt

    Name           : AggregatorHost
    Id             : 3956
    Path           : C:\Windows\System32\AggregatorHost.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 198b9c5a-5cd9-4e85-baba-b9c6b83864b8

    Name           : conhost
    Id             : 7156
    Path           : C:\Windows\system32\conhost.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 198b9c5a-5cd9-4e85-baba-b9c6b83864b8

    Name           : ctfmon
    Id             : 1684
    Path           : C:\Windows\system32\ctfmon.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 198b9c5a-5cd9-4e85-baba-b9c6b83864b8

    Name           : dfsrs
    Id             : 3208
    Path           : C:\Windows\system32\DFSRs.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 198b9c5a-5cd9-4e85-baba-b9c6b83864b8

    Name           : dfssvc
    Id             : 3500
    Path           : C:\Windows\system32\dfssvc.exe
    PSComputerName : 10.50.22.95
    RunspaceId     : 198b9c5a-5cd9-4e85-baba-b9c6b83864b8

# Using the same methodology, query and store network information. We can still see our remote WinRM connection, even though it is not persistent, using Invoke-Command
PS C:\Users\student\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {Get-NetTCPConnection | Select-Object -Property LocalAddress,LocalPort,RemoteAddress | Where-Object {$_.LocalPort -eq '5985'}} | Select-Object -Last 2

    LocalAddress   : 10.50.22.95
    LocalPort      : 5985
    RemoteAddress  : 10.50.33.11
    PSComputerName : 10.50.22.95
    RunspaceId     : d1a12a86-ba41-42ac-a439-ef95734ffaa6

    LocalAddress   : 10.50.22.95
    LocalPort      : 5985
    RemoteAddress  : 10.50.33.11
    PSComputerName : 10.50.22.95
    RunspaceId     : d1a12a86-ba41-42ac-a439-ef95734ffaa6

PS C:\Users\student\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {Get-NetTCPConnection | Select-Object -Property LocalAddress,LocalPort,RemoteAddress | Where-Object {$_.LocalPort -eq '5985'}} | Select-Object -Last 2 | Out-File -FilePath C:\Users\student\Desktop\DomainControllerNetwork.txt

PS C:\Users\student\Desktop> Get-Content .\DomainControllerNetwork.txt

    LocalAddress   : 10.50.22.95
    LocalPort      : 5985
    RemoteAddress  : 10.50.33.11
    PSComputerName : 10.50.22.95
    RunspaceId     : 6a39bfc2-4a58-4820-859d-351964246e71

    LocalAddress   : 10.50.22.95
    LocalPort      : 5985
    RemoteAddress  : 10.50.33.11
    PSComputerName : 10.50.22.95
    RunspaceId     : 6a39bfc2-4a58-4820-859d-351964246e71
```

**Important**

Using Invoke-Command as opposed to Enter-PSSession on a known-compromised Windows host is the better alternative if you have no physical access to the host. Invoke-Command does not establish a persistent session, reducing the potential for exposure to an adversary.

**Using Invoke-Command to create or modify files on a remote system.**
```
# Start by creating a saving a script on the remote computer using the Set-Content cmdlet
PS C:\Users\student\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {$Content = "cmd.exe /c ping -n 1 10.50.35.169"; $FilePath = "C:\Users\Administrator\Desktop\pingme.ps1"; Set-Content -Path $FilePath -Value $Content}

# Execute the script using Invoke-Command and view the results
PS C:\Users\student\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {powershell.exe "C:\Users\Administrator\Desktop\pingme.ps1"}

    Pinging 10.50.35.169 with 32 bytes of data:
    Reply from 10.50.35.169: bytes=32 time=6ms TTL=128

    Ping statistics for 10.50.35.169:
        Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
    Approximate round trip times in milli-seconds:
        Minimum = 6ms, Maximum = 6ms, Average = 6ms

# Altering the code within the script to receive different results using Set-Content to overwrite the previous code
PS C:\Users\student\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {$NewContent = "cmd.exe /c ping -n 5 10.50.35.169"; $FilePath = "C:\Users\Administrator\Desktop\pingme.ps1"; Set-Content -Path $FilePath -Value $NewContent}

PS C:\Users\student\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {powershell.exe "C:\Users\Administrator\Desktop\pingme.ps1"}

    Pinging 10.50.35.169 with 32 bytes of data:
    Reply from 10.50.35.169: bytes=32 time=9ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=11ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=1ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=1ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=1ms TTL=127

    Ping statistics for 10.50.35.169:
        Packets: Sent = 5, Received = 5, Lost = 0 (0% loss),
    Approximate round trip times in milli-seconds:
        Minimum = 1ms, Maximum = 11ms, Average = 4ms

# Appending new code to the script with the Add-Content cmdlet to receive the original and new results, you may need the back tick "`" escape character for some special characters to work properly in a ScriptBlock
PS C:\Users\student\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {$NewContent = "Get-Process | Select-Object -Property Name,Path | Where-Object {`$_.Name -like `"pwsh`"}"; $FilePath = "C:\Users\Administrator\Desktop\pingme.ps1"; Add-Content -Path $FilePath -Value $NewContent}

PS C:\Users\student\Desktop> Invoke-Command -ComputerName 10.50.22.95 -Credential $Creds -ScriptBlock {powershell.exe "C:\Users\Administrator\Desktop\pingme.ps1"}

    Pinging 10.50.35.169 with 32 bytes of data:
    Reply from 10.50.35.169: bytes=32 time=13ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=6ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=1ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=1ms TTL=127
    Reply from 10.50.35.169: bytes=32 time=1ms TTL=127

    Ping statistics for 10.50.35.169:
        Packets: Sent = 5, Received = 5, Lost = 0 (0% loss),
    Approximate round trip times in milli-seconds:
        Minimum = 1ms, Maximum = 13ms, Average = 4ms

    Name Path
    ---- ----
    pwsh C:\Program Files\PowerShell\7\pwsh.exe
```