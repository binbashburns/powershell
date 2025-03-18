# The Pipeline

Pipelines are used regularly in command line interface interaction, so it is important to understand how to format and manipulate objects in the PowerShell pipeline. Old consoles were able to forward (or "pipe") the results of a command to the next with the "pipe" operator "|". In contrast to the traditional concept of text piping, the PowerShell pipeline takes an object-oriented approach and implements it in real time.

The PowerShell pipeline is always used, even when you only provide a single command. PowerShell attaches the Out-Default cmdlet to your input, which converts the resulting objects into text at the end of the pipeline.

The pipeline is a series of commands where the output of one becomes the input of the next.

# Formatting Pipeline Output

There are 4 types of formatting cmdlets.

**Formatting Cmdlets.**
```
Get-Command -verb format
```
   - Display certain properties

   - Change column Headings

   - Grouping Using Formatting Cmdlets

**Displaying certain properties.**
```
Get-Service | Format-Table Name, Status
```
**Display the name of each item in the current directory.**
```
Get-ChildItem | Format-Table Name
```
[Source](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/format-table?view=powershell-7.3)

PowerShell shows only so much information by default. You will have to use *Format-Table* to view all the object properties.

**View all Running Services using Format-Table.**
```
Get-Service | Format-Table
```
Since the output of the previous cmdlet is too much information to shrink it onto the terminal. We will use a different formatting cmdlet called *Format-List*

**View all Running Services using Format-List.**
```
Get-Service | Format-List
```
## Comparison Operators

| Operator | Description |
|---|---|
|-eq, -ceq | Equals|
|-ne, -cne | Not Equal|
|-gt, -cgt | Greater Than|
|-lt, -clt | Less Than|
|-ge, -cge | Greater Than or Equal To|
|-le, -cle | Less Than or Equal To|
|-like, -clike | String matches wildcard pattern|
|-notlike, -cnotlike | String does not match wildcard pattern|
|-match, cmatch | String matches regex pattern|
|-notmatch, -cnotmatch | String does not match regex pattern|
|-replace, -creplace | replaces strings matching a regex pattern|
|-contains, -ccontains | Contains (used for a collection of items)|
|-notcontains, -cnotcontains | Collection does not contain a value|
|-in | Returns true when value is contained within a collection|
|-notin |Value is not in a collection|
|-is | Returns true if both objects are the same type|
|-isnot | The objects are not the same type|

**Note**
String comparisons are case-insensitive unless you explicitly use the case-sensitive operator. To make a comparison operator case-sensitive, add a c after the -. For example, -ceq is the case-sensitive version of -eq. To make the case-insensitivity explicit, add an i after -. For example, -ieq is the explicitly case-insensitive version of -eq.

**Equals.**
```
PS C:\> '192.168.1.1' -eq '192.168.1.1'
    True

PS C:\> '192.168.1.1' -eq '192.168.1.2'
    False
```
**Not Equals.**
```
PS C:\> '192.168.1.1' -ne '192.168.1.2'
    True

PS C:\> '192.168.1.1' -ne '192.168.1.1'
    False
```
**Greater Than.**
```
PS C:\> '192.168.1.254' -gt '192.168.1.1'
    True

PS C:\> '192.168.1.254' -gt '192.168.1.255'
    False
```
**Less Than.**
```
PS C:\> '192.168.1.254' -lt '192.168.1.255'
    True

PS C:\> '192.168.1.254' -lt '192.168.1.1'
    False
```
**Greater Than or Equal To.**
```
PS C:\> '192.168.1.254' -ge '192.168.1.1'
    True

PS C:\> '192.168.1.254' -ge '192.168.1.254'
    True

PS C:\> '192.168.1.254' -ge '192.168.1.255'
    False
```
**Less Than or Equal To.**
```
PS C:\> '192.168.1.254' -le '192.168.1.255'
    True

PS C:\> '192.168.1.254' -le '192.168.1.254'
    True

PS C:\> '192.168.1.254' -le '192.168.1.1'
    False
```
### Like

Returns true when a string matches a wildcard pattern. There are four types of wildcard characters that ***-like*** and ***-notlike*** support.

   - The * wildcard matches zero or more characters

   - The ? will match a single character

   - [a-z] will match a range of characters from a to z

   - [def] will match a set of characters

**like**
```
PS C:\> "PowerShell" -like "*shell"
    True

PS C:\> "PowerShell", "Server" -like "*shell"
    PowerShell
```
### Not Like

Returns true when string does not match wildcard pattern

**notlike**
```
PS C:\> "PowerShell" -notlike "shell*"
    True

PS C:\> "PowerShell", "Server" -notlike "*shell"
    Server
```
### match

Returns true when a string matches a regex pattern.

**match** 
```
PS C:\> $text1 = 'Here is the serial number: MO5364'
PS C:\> $text2 = 'Here is the serial number: MO65'
PS C:\> $pattern = 'MO(\d{3})'
PS C:\> $text1 -match $pattern
    True
PS C:\> $text2 -match $pattern
    False

PS C:\> $IP1 = '192.168.1.256'

PS C:\> $IP2 = '192.168.218.254'

PS C:\> $pattern = '^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'

PS C:\> $IP1 -match $pattern
    False

PS C:\> $IP2 -match $pattern
    True
```
### Contains

Tests for the existence of one item in a collection of items

**contains**
```
PS C:\> $IPs = '10.50.25.255', '10.35.192.253', '192.168.1.5', '10.50.22.95'

PS C:\> $IPs -contains '10.25.192.253'
    True
```
# Functions

A function is a list of PowerShell statements that has a name that you assign. When you run a function, you type the function name. The statements in the list run as if you had typed them at the command prompt.

[Microsoft Docs: about_functions](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions?view=powershell-7.3)

## Identify Basic Functions

Just like other scripting languages, Windows PowerShell has the ability to create functions. Functions are new commands made up of PowerShell script blocks. The syntax of a function looks like the following:

**Function Syntax**
```
function <name> {
        code to execute
    }
```
## Demonstrate Functions

**Example 1 Getting Processes**
```
PS C:\> function processes {
            Get-Process
        }

PS C:\> processes
    NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
    ------    -----      -----     ------      --  -- -----------
        26    25.05       4.96       0.19   21124   5 AcrobatNotificationClient
        26     7.85      22.82       9.28   17488   5 AdobeCollabSync
        19     4.95      19.17       0.11   17820   5 AdobeCollabSync
```
**Example 2 Getting Network Information**
```
PS C:\> function network{
            Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Where-Object -Property State -eq "Listen"
        }

PS C:\> network
    LocalAddress  : 192.168.177.1
    LocalPort     : 139
    RemoteAddress : 0.0.0.0
    RemotePort    : 0
    State         : Listen
    OwningProcess : 4

    LocalAddress  : 192.168.1.69
    LocalPort     : 139
    RemoteAddress : 0.0.0.0
    RemotePort    : 0
    State         : Listen
    OwningProcess : 4

    LocalAddress  : 0.0.0.0
    LocalPort     : 135
    RemoteAddress : 0.0.0.0
    RemotePort    : 0
    State         : Listen
    OwningProcess : 1084
```
**Example 3 Getting Network and Processes (Function using a PSCustomObject)**
```
PS C:\> function PNN{
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

PS C:\> PNN
    LocalAddress  LocalPort RemoteAddress RemotePort  State ProcessId ProcessName  ProcessPath
    ------------  --------- ------------- ----------  ----- --------- -----------  -----------
    0.0.0.0             902 0.0.0.0                0 Listen      4248 vmware-authd C:\Program Files (x86)\VMware\VMware Workstation\vmware-authd.exe
    192.168.195.1       139 0.0.0.0                0 Listen         4 System
    192.168.177.1       139 0.0.0.0                0 Listen         4 System
    192.168.1.69        139 0.0.0.0                0 Listen         4 System
    0.0.0.0             135 0.0.0.0                0 Listen      1084 svchost      C:\Windows\system32\svchost.exe
```
### Demonstrate Parameters

Parameters in PowerShell functions are used to make functions more flexible and reusable.

**Example 4 Designing a Basic Function with Custom Parameters**
```
PS C:\> function UserInfo {
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

PS C:\> UserInfo -Username Administrator -IncludeDetails
    Getting detailed information for user Administrator

    Name          Enabled PasswordRequired SID
    ----          ------- ---------------- ---
    Administrator   False             True S-1-5-21-3780157036-4114611373-2348294647-500

PS C:\> UserInfo -Username Administrator
    Getting basic information for user Administrator

    Name          Enabled
    ----          -------
    Administrator   False
```
# File IO

## Identify Out-File

The Out-File cmdlet sends output to a file. It implicitly uses PowerShell’s formatting system to write to the file. The file receives the same display representation as the terminal.

[Microsoft Docs: Outfile](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-file?view=powershell-7.3)

Outfile uses the following syntax:
```
Out-File [-FilePath] <string> [[-Encoding] <Encoding>] [-Append] [-Force] [-NoClobber] [-Width <int>] [-NoNewline] [-InputObject <psobject>] [-WhatIf] [-Confirm] [<CommonParameters>]
```
### Demonstrate Out-File

**Out-File**
```
PS C:\> Get-LocalUser | Out-File -FilePath .\user.txt
```
## Identify Get-Content

The Get-Content cmdlet gets the content of the item at the location specified by the path, such as the text in a file or the content of a function. For files, the content is read one line at a time and returns a collection of objects, each of which represents a line of content.

[Microsoft Docs: Get-Content](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content?view=powershell-7.3)

### Demonstrate Get-Content

**Get-Content**
```
PS C:\> Get-Content -Path .\user.txt
        Administrator
        DefaultAccount
        Guest
        student
        WDAGUtilityAccount
```
## Identify Add-Content

The Add-Content cmdlet appends content to a specified item or file. You can specify the content by typing the content in the command or by specifying an object that contains the content.

[Microsoft Docs: Add-Content](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-content?view=powershell-7.3)

### Demonstrate Add-Content

**Add-Content**
```
PS C:\> $User = (Get-LocalUser).Name

PS C:\> Add-Content -Path .\testfile.txt -Value $User
```
**Add-Content Using Pipeline**
```
#Running this command on PowerShell 5 will result in an error when using the pipeline.

PS C:\> Get-Content -Path .\testfile.txt | Add-Content -Path .\testfile.txt

PS C:\> Get-Content .\testfile.txt
    Administrator
    DefaultAccount
    Guest
    student
    WDAGUtilityAccount
    Administrator
    DefaultAccount
    Guest
    student
    WDAGUtilityAccount
```
## Identify Set-Content

Set-Content is a string-processing cmdlet that writes new content or replaces the content in a file. Set-Content replaces the existing content and differs from the Add-Content cmdlet that appends content to a file. To send content to Set-Content you can use the Value parameter on the command line or send content through the pipeline.

[Microsoft Docs: Set-Content](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content?view=powershell-7.3)

### Demonstrate Set-Content

**Set-Content**
```
PS C:\> Set-Content -Path .\testfile.txt -Value (Get-LocalGroup).name

PS C:\> Get-Content -Path .\testfile.txt
    Access Control Assistance Operators
    Administrators
    Backup Operators
    Cryptographic Operators
    Device Owners
    Distributed COM Users
    Event Log Readers
    Guests
    Hyper-V Administrators
    IIS_IUSRS
    Network Configuration Operators
    Performance Log Users
    Performance Monitor Users
    Power Users
    Remote Desktop Users
    Remote Management Users
    Replicator
    System Managed Accounts Group
    Users
```
## Export-CSV

The Export-CSV cmdlet creates a CSV file of the objects that you submit. Each object is a row that includes a character-separated list of the object’s property values. You can open the resulting file with applications such as Microsoft Excel or Libre Office Calc to visualize and further modify the results.

[Microsoft Docs: Export-CSV](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-csv?view=powershell-7.3)

**Export-CSV**
```
PS C:\> Get-Process -Name svchost | Export-Csv -path C:\Users\student\Desktop\svchost.csv
```
## Import-CSV

The Import-Csv cmdlet creates table-like custom objects from the items in CSV files. Each column in the CSV file becomes a property of the custom object and the items in rows become the property values. Import-Csv works on any CSV file, including files that are generated by the Export-Csv cmdlet.

[Microsoft Docs: Import-CSV](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/import-csv?view=powershell-7.3)

**Import-CSV**
```
PS C:\> Import-Csv -Path C:\users\student\Desktop\svchost.csv
```
### Converting Logs into a Usable Format for a SIEM (Security Information and Event Management)

PowerShell can be used to easily modify event log data and convert it into a format to be used by tools like Logstash, Elasticsearch, and Kibana. A common format used is JSON. Once the event data has been converted, most GUI based SIEMs have a simple method for uploading the resulting JSON file. However, that will not be demonstrated here, as it is outside the scope of this class.

## ConvertTo-JSON

The ConvertTo-Json cmdlet takes walls of Windows event log text and places it into a format that can be indexed by the aforementioned tools.

**ConvertTo-Json**
```
PS C:\> $events = Get-WinEvent -LogName Security -MaxEvents 10

PS C:\> $eventsJSON = $events | ConvertTo-Json -Depth 5

PS C:\> $eventsJSON | Out-File -FilePath events.json

PS C:\> Get-Content .\events.json        #Below is a partial example of the output.
    {
        "Value": "C:\\Windows\\System32\\svchost.exe"
        },
        {
        "Value": {
            "BinaryLength": 12,
            "AccountDomainSid": null,
            "Value": "S-1-16-8192"
        }
        }
    "Message": "A new process has been created.
```
# PowerShell Modules

PowerShell modules are packages of cmdlets, providers, functions, variables, and aliases. They are loaded on first use and they can be unloaded or reloaded during a session.

## Finding Modules

Published PowerShell modules can be installed from two sources Install-Module and Install-PSResource. Pre-loaded modules can also be listed with the **Get-Module** cmdlet. Running cmdlets associated with a module with load the module automatically.

**Installing Published PowerShell Modules**
```
PS C:\> Get-Command Install-Module, Install-PSResource
    CommandType     Name                                               Version    Source
    -----------     ----                                               -------    ------
    Function        Install-Module                                     2.2.5      PowerShellGet
    Cmdlet          Install-PSResource                                 1.0.1      Microsoft.PowerShell.PSResourceGet

PS C:\> Get-Module
    ModuleType Version    PreRelease Name                                ExportedCommands
    ---------- -------    ---------- ----                                ----------------
    Manifest   1.0.0.0               DnsClient                           {Resolve-DnsName, Add-DnsClientNrptRule, Clear-DnsClientCache, Get-DnsClient…}
    Manifest   7.0.0.0               Microsoft.PowerShell.Management     {Add-Content, Clear-Content, Clear-Item, Clear-ItemProperty…}
    Binary     1.0.1                 Microsoft.PowerShell.PSResourceGet  {Find-PSResource, Get-InstalledPSResource, Get-PSResourceRepository, Get-PSScriptFileInfo…}
    Manifest   7.0.0.0               Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object…}
    Manifest   1.0.0.0               NetTCPIP                            {Find-NetRoute, Get-NetCompartment, Get-NetIPAddress, Get-NetIPConfiguration…}
    Script     1.4.8.1               PackageManagement                   {Find-Package, Find-PackageProvider, Get-Package, Get-PackageProvider…}
    Script     2.2.5                 PowerShellGet                       {Find-Command, Find-DscResource, Find-Module, Find-RoleCapability…}
    Script     2.3.4                 PSReadLine                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PSReadLineKeyHandler, Set-PSReadLineKeyHandler…}
```
## PowerShell NetTCPIP Module

**Using the PowerShell NetTCPIP Module**
```
PS C:\> Get-Command -Module NetTCPIP
    CommandType     Name                                               Version    Source
    -----------     ----                                               -------    ------
    Function        Find-NetRoute                                      1.0.0.0    NetTCPIP
    Function        Get-NetCompartment                                 1.0.0.0    NetTCPIP
    Function        Get-NetIPAddress                                   1.0.0.0    NetTCPIP
    Function        Get-NetIPConfiguration                             1.0.0.0    NetTCPIP

PS C:\> Get-NetIPAddress | Select-Object -First 5 -Property IPAddress, InterfaceIndex
    IPAddress       interfaceindex
    ---------       --------------
    10.250.0.80                 17
    169.254.23.209               5
    192.168.1.69                 3
    169.254.245.234             12
    127.0.0.1                    1
```
## PowerShell DnsClient Module

**Using the PowerShell DnsClient Module**
```
PS C:\> Get-DnsClient | Select-Object -Property InterfaceAlias, InterfaceIndex
    InterfaceAlias                InterfaceIndex
    --------------                --------------
    OpenVPN Wintun                            12
    Ethernet                                   3
    OpenVPN TAP-Windows6                       5
    OpenVPN Data Channel Offload              17

PS C:\> Get-DnsClientServerAddress | Select-Object -Property InterfaceAlias, ServerAddresses
    InterfaceAlias                ServerAddresses
    --------------                ---------------
    Ethernet                      {192.168.1.1}
    tap89ea3c76-5a                {10.255.255.254, 8.8.8.8}
```
## PowerShell RSAT Module

RSAT or Remote Server Administration Tools, is a set of tools that allows an administrator to remotely manage roles and features in Windows Servers. To begin using RSAT, you can install it using PowerShell.

**Installing the PowerShell RSAT Module**
```
PS C:\> Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
    Operation [Running]        #This might take some time to complete

    Path          :
    Online        : True
    RestartNeeded : False
```
**Note**
You will need credentials to run remote active directory commands on the Domain Controller if your host is not a member of the target domain.

**Using the PowerShell RSAT Module Active Directory Cmdlets**
```
# To demonstrate RSAT, first enter a remote PowerShell session to the Domain Controller.
PS C:\Windows\System32> Enter-PSSession -ComputerName 10.50.22.95 -Credential $creds
[10.50.22.95]: PS C:\Users\Administrator\Documents>

# Show Domain Users
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-ADUser -Filter * | Select-Object -Property Name, SID -First 5
    Name           SID
    ----           ---
    Administrator  S-1-5-21-3266719963-742974059-281163612-500
    Guest          S-1-5-21-3266719963-742974059-281163612-501
    cloudbase-init S-1-5-21-3266719963-742974059-281163612-1000
    Admin          S-1-5-21-3266719963-742974059-281163612-1001
    krbtgt         S-1-5-21-3266719963-742974059-281163612-502

# Show Domain Groups
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-ADGroup -Filter * | Select-Object -Property Name, SID -First 5
    Name             SID
    ----             ---
    Administrators   S-1-5-32-544
    Users            S-1-5-32-545
    Guests           S-1-5-32-546
    Print Operators  S-1-5-32-550
    Backup Operators S-1-5-32-551

# Show Domain Computer Name
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-ADComputer -Filter * | Select-Object -Property Name -First 10 | Format-Table
    Name
    ----
    POWERSHELL-PEDC

# Show Domain Information
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-ADDomain | Select-Object -Property Name, DNSRoot, Forest, DomainSID | Format-List
    Name      : PSPE
    DNSRoot   : PSPE.mil
    Forest    : PSPE.mil
    DomainSID : S-1-5-21-3266719963-742974059-281163612
```
Read more about RSAT [here](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools) and [here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_modules?view=powershell-7.4)