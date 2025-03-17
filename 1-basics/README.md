# Introduction

Windows PowerShell® is a task-based command-line shell and scripting language designed especially for system administration. Built on the .NET Framework, Windows PowerShell helps IT professionals and power users control and automate the administration of the Windows operating system and applications that run on Windows.

## .NET Framework

The .NET framework provides a consistent object-oriented programming environment that consists of the common language runtime (CLR) and the .NET Framework class library.

## Launching PowerShell

   - Click Start, type PowerShell, and then click Windows PowerShell or the ISE

   - From the Start menu, click Start, click All Programs, click Accessories, click the Windows PowerShell folder, and then click Windows PowerShell

   - In cmd.exe type `PowerShell` to run PowerShell 5.1 or `pwsh` to run PowerShell Core

   - Click Start, type PowerShell, right-click Windows PowerShell or PowerShell 7, and then click Run as Administrator

## Running Cmdlets

### Commands vs Cmdlets

Windows PowerShell commands are called cmdlets (command-lets). Cmdlets use a verb-noun structure for calling cmdlets. One of the most useful cmdlets is the get-command cmdlet.

**List all commands available to PowerShell.**

```
Get-Command
```

This command displays a long list of available cmdlets. If you are looking to retrieve an item or information about something, then you would use the verb “get"

```
Get-Command
```
```
...
Alias Set-EtwTraceSession 1.0.0.0 EventTracingManagement 
Alias Set-ProvisionedAppPackageDataFile 3.0 Dism 
Alias Set-ProvisionedAppXDataFile 3.0 Dism 
Alias Write-FileSystemCache 2.0.0.0 Storage 
Function A: 
Function Add-BitLockerKeyProtector 1.0.0.0 BitLocker 
Function Add-DnsClientNrptRule 1.0.0.0 DnsClient 
Function Y: 
Function Z: 
Cmdlet Add-AppxPackage 2.0.1.0 Appx 
Cmdlet Add-AppxProvisionedPackage 3.0 Dism 
Cmdlet Add-AppxVolume 2.0.1.0 Appx 
Cmdlet Add-BitsFile 2.0.0.0 BitsTransfer
...
```

**List all verbs available to Powershell.**
```
Get-Verb
```
```
Verb        Group
----        -----
Add         Common
Clear       Common
Close       Common
Copy        Common
Enter       Common
```

If you want to display all available cmdlets that begin with “get"

**List verb cmdlets.**
```
Get-Command -Verb Get
```
If you wanted to list all of the cmdlets that have to do with processes, you would use the -noun parameter
```
Get-Command -Noun Process
```
### Case Insensitive

Powershell is case insensitive, meaning capital letters and lowercase letters are treated the same.

### Singular

Powershell use singular nouns so the command to get all processes is Get-Process rather than Get-Processes

## Internal vs External

External commands are commands not native to PowerShell and the output of these commands return strings. Internal commands are cmdlets and the output returns objects instead of strings.

**External command.**
```
tasklist
```
**Internal Command.**
```
Get-Process
```
## Cmdlet Anatomy

**Full-form Syntax.**
```
Get-WinEvent  
```
```
    - LogName 'Windows PowerShell'
    - ComputerName Server1
    - Verbose
```
   - The cmdlet name. Verb-Noun Format

   - The first parameter with the value *'Windows PowerShell'*

   - The second named parameter with the value *Server1*

   - Switch parameter, no value, good just by itself

## Cmdlet Naming Convention

   - **Cmdlet**:
       - Native to PowerShell and are written in .NET Framework Language like C#.

   - **Function**:
       - Similar to a cmdlet but written in PowerShell scripting language instead of the .NET Framework.

   - **Workflow**:
       - Special kind of function that ties into PowerShell’s workflow execution system.

   - **Application**:
       - External executable, including command-line utilities such as Ping and IPconfig.

   - **Command**:
       - Generic term to refer to any or all preceding terms

## Command Search Order Execution

When a command is executed without its full path, PowerShell searches for the command’s name in a specific search order trying to match it.

The order is as follows:

   1. Aliases

   2. Functions

   3. Cmdlets

   4. Path Environment commands

**Note**
This is important because if you create an alias that has different behavior than a command, PowerShell will run the alias first.

## The Help System

Getting help in PowerShell is similar to getting help on any other CLI or API. We will start by typing the following commands and examining their output.
```
Get-Help
```
This should display the Windows PowerShell help screen. There are many different ways to display help with PowerShell and with using parameters, you are able to narrow down or get the specific information you are seeking.

### Using Help

You may first want to update-help to the latest version.

**Updating Help.**
```
Update-Help -Force -ErrorAction SilentlyContinue
```
**Using Help.**
```
Get-Help Get-Command
```
Powershell will not present you with the full help page unless you specifically request the full page. By default, it will give you a truncated page.

**Get the full help page.**
```
Get-Help Get-Process -Full
```
**Using Help to find commands.**
```
Get-Help *log*
Get-Help *event*
```
Sometimes, you may want to view examples of commands with Powershell.

**Get Help Examples.**
```
Get-Help Get-Process -Examples
```
About topics cover a range of concepts about PowerShell.

**Using About Topics.**
```
Get-Help about_*
```
View the Help File in a web browser

**Online.**
```
Get-Help Get-Process -Online
```
You may not have internet access so you can view help documentation in a resizable and searchable window on your system
```
Get-Help Get-Process -ShowWindow
```
## Help Syntax
|symbol|description|
|---|---|
| - | Indicates a parameter |
| <> |  Indicates Arguments |
|[] | Argument accepts multiple values|

# Variables and Parameters

Windows PowerShell works with objects and allows you to store those objects in variables. A variable is a unit of memory in which values are stored. When working with large data sets in PowerShell, it is better to store that data into an object variable before performing formatting on that data. In PowerShell, variables are represented by text strings that begin with a dollar sign ($). 

## User-created variables

   - Assign Values

   - Assign Multiple Variables

   - Different Values, Multiple Variables

**List current variables available to your PowerShell session.**
```
Get-Variable
```
**Output specific variable.**
```
$proc = Get-Process
Get-Variable proc
```
**Assign Multiple Variables.**
```
PS C:\> $proc = Get-Process; $net = Get-NetTCPConnection; $pwd = Get-ChildItem

    PS C:\> $proc
        NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
        ------    -----      -----     ------      --  -- -----------
            27    25.09       0.16       0.34    1256   6 AdobeNotificationClient
            10     1.95       1.09       0.19    4532   0 AdobeUpdateService
            14    19.94       5.99       0.34   20368   6 ai
            21    12.37      12.81       0.27    9220   6 ApplicationFrameHost
                8     1.55       0.24       0.00    4948   0 armsvc
    PS C:\> $net
        LocalAddress                        LocalPort RemoteAddress                       RemotePort State       AppliedSetting OwningProcess
        ------------                        --------- -------------                       ---------- -----       -------------- -------------
        127.0.0.1                           65001     127.0.0.1                           56600      Established Internet       636
        127.0.0.1                           65001     0.0.0.0                             0          Listen                     636
        192.168.1.69                        57620     52.245.136.46                       443        Established Internet       15240
        192.168.1.69                        57619     172.64.154.54                       443        TimeWait                   0
    PS C:\> $pwd
        Mode                 LastWriteTime         Length Name
        ----                 -------------         ------ ----
        d-r--          12/13/2020  5:02 PM                Contacts
        d-r--           1/11/2021 10:36 AM                Creative Cloud Files
        d-r--            1/3/2024  5:00 PM                Desktop
        d-r--           12/5/2023  4:51 PM                Documents
        d-r--            1/3/2024  5:53 PM                Downloads
```
**Verify a variable using Test-Path, it should return "True".**
```
Test-Path variable:proc
```
**Deleting Variables.**
```
Remove-Variable proc,net,pwd
```
## Automatic Variables

In Windows PowerShell, there are variables that are created and maintained by PowerShell itself. These are called automatic variables. Automatic variables store state information for internal purposes and are available after you launch your instance of PowerShell.

**List Automatic Variables.**
```
Get-Variable
```

|Variable | Description|
|---|---|
|$False | False|
|$True | True|
|$Null | Empty value|
|$$ | Last Token used|
|$?|  Execution status of last operation|
|$^ | First Token in last line received|
|$_ or $PSItem | Object in current pipeline|
|$Args | Array of undeclared parameters and/or values|
|$Error | Most recent error|
|$Home| full path of user’s home directory|
|Host |Current host application|
|Input | Enumerator that enumerates all input passed to a function|
|$LastExitCode | exit code of the last Windows-based program that was run|
|$Matches  | Hash Table of RegEx matches|
|$PID | PID of current PS session|
|$Profile | Full path of current user and host application|
|$PSVersionTable | Details about Windows PowerShell|
|$PSHome | the full path of the installation directory for PowerShell|
|$Pwd |Full path of current directory|

A full list of automatic variables and their functions can be found [here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables?view=powershell-7.4#long-description.)

## Variable Description.
```
Get-Variable | Sort-Object Name | Format-Table Name, Description -autosize -wrap
```
## Environment Variables

There are special types of variables called environmental variables. Unlike local variables, these stay consistent in every session and make it possible for them to be used by other programs. Environment variables are stored in “env:”.

**List env: variables.**
```
Get-ChildItem env:
```
You use environment variables just like you would call a local variable. For example, you would use the following cmdlet to display user information using environment variables.

**env: variable example.**
```
$env:userprofile
```
Like local variables, you are able to create and delete environmental variables. This is done the same way as making local variables.

**Creating & Deleting Environment Variables.**
```
$env:var = "Hello"

$env:var
Hello

del env:var
```
## Variable Types

When you use variables to store information, PowerShell automatically assigns a data type. There are many common data types assigned in Windows PowerShell.
|Type |	Description|
|---|---|
|[string] |Fixed-length string of unicode characters|
|[char]| 16-bit unicode character|
|[byte] |8-bit unsigned character|
|[int] |32-bit signed integer|
|[long] |64-bit signed integer|
|[single] |32-bit floating point number|
|[double] |64-bit floating point number|
|[datetime] |Date and Time|
|[array] |array of values|

If you are unsure about the data type that PowerShell assigned to a variable, then append *_.GetType() to the variable. Based on the output, we can see that the $proc variable is an Object[] and has a base type of System.Array.

**Viewing Variable type.**
```
PS C:\> $proc = Get-Process
PS C:\> ($proc).GetType()
    IsPublic IsSerial Name                                     BaseType
    -------- -------- ----                                     --------
    True     True     Object[]                                 System.Array
```
## Parameter Sets

**Get-Help Get-Service.**
```
Get-Help Get-Service
```
The cmdlet under "SYNTAX" is listed three times and indicates that the cmdlet supports three parameter sets. This means that the cmdlet can be use in three different ways.

### Named Parameters

Named parameters work kind of like key-value pairs. You specify the parameter using a hyphen followed by the parameter name, then a space, then the value you want to assign to the parameter.

**Named Parameter: list the process with the process ID of 4.**
```
Get-Process -Id 4
```
### Switch Parameters

When a parameter represents a boolean value, usually a switch parameter is used as present or not.
When we run *Get-Help Get-Childitem -Full*, the *-recurse* parameter is labeled as "<System.Management.Automation.SwitchParameter>"
```
Get-Help Get-ChildItem -Full

Get-ChildItem -Recurse
```
### Positional Parameters

Parameters that have fixed positions. These positional parameters do not require the user to explicitly call the named parameter and only require the user to type the arguments in relative order.

**Positional Parameter: List the contents of the C:\Windows path. The -path parameter is a positional parameter.**
```
Get-ChildItem -path C:\Windows

Get-ChildItem C:\Users
```
# Objects

PowerShell objects provide a consistent structure for working with types of data. To work with object data, you call its members; two common member types are:

## Properties

Properties describe an object.

   - Sample Properties of a Cyber Warrant Officer object

       - Name - Joe Cyber

       - Rank - Warrant Officer One

       - MOS - 170A

       - Unit - United States Army Cyber School

## Methods

Methods are things that an object can do. When you output an object to the console, only its properties are converted into readable text. Its methods remain invisible.

   - Sample Methods of a Cyber Warrant Officer object

       - SolveProblems()

       - EnumerateNetwork()

       - BaselineNetwork()

       - PlanMission()

       - IntegrateTechnology()

       - ExploitVulnerability()

**Get a Process Property.**
```
(Get-Process).ProcessName
(Get-Process).ID
```
**Stop a Process by invoking a method.**
```
(Get-Process notepad).Kill()
```
Properties of an object store data, and the data is in turn stored in various other objects.

**View Properties and Methods using Get-Member.**
```
Get-Service | Get-Member
Get-Member -InputObject Get-Service
```
# Get-Member Command

**List all available members for a given command.**
```
Get-Process | Get-Member

    TypeName: System.Diagnostics.Process

Name                       MemberType     Definition
----                       ----------     ----------
Handles                    AliasProperty  Handles = Handlecount
Name                       AliasProperty  Name = ProcessName
NPM                        AliasProperty  NPM = NonpagedSystemMemorySize64
PM                         AliasProperty  PM = PagedMemorySize64
SI                         AliasProperty  SI = SessionId
VM                         AliasProperty  VM = VirtualMemorySize64
WS                         AliasProperty  WS = WorkingSet64
Disposed                   Event          System.EventHandler Disposed(System.Object, System.EventArgs)
ErrorDataReceived          Event          System.Diagnostics.DataReceivedEventHandler ErrorDataReceived(System.Objec...
Exited                     Event          System.EventHandler Exited(System.Object, System.EventArgs)
OutputDataReceived         Event          System.Diagnostics.DataReceivedEventHandler OutputDataReceived(System.Obje...
WaitForExit                Method         bool WaitForExit(int milliseconds), void WaitForExit()
WaitForInputIdle           Method         bool WaitForInputIdle(int milliseconds), bool WaitForInputIdle()
__NounName                 NoteProperty   string __NounName=Process
BasePriority               Property       int BasePriority {get;}
Container                  Property       System.ComponentModel.IContainer Container {get;}
EnableRaisingEvents        Property       bool EnableRaisingEvents {get;set;}
```
**List properties of the Get-Process command.**
```
Get-Process | Get-Member -MemberType Properties
```
**List methods of the Get-Process command.**
```
Get-Process | Get-Member -MemberType method
```
# Logging

Logging in PowerShell is very important from both an offensive and defensive perspective. You want PowerShell logging to be enabled as a defender, so you are aware of the PowerShell commands and scripts that are running on the network. You prefer logging to be disabled from an offensive perspective, so it is more difficult to know what actions you are taking as an attacker using PowerShell.

## PowerShell Transcripts

A useful tool for keeping track of your operational notes or OPNOTES is PowerShell transcripts. Transcripts allow you to log all commands in a current PowerShell session and save their output to a text file.

**Enable PowerShell transcript: Save all of the commands run in your current PowerShell session by running a transcript command..** 
```
PS C:\> $transcript = "C:\Users\Student\Desktop\transcript.log"
PS C:\> Start-Transcript -path $transcript
    Transcript started, output file is C:\Users\student\Desktop\transcript.log
```

**Stopping your transcript: Once you are finished in your PowerShell session, remember to run the Stop-Transcript command..**
```
PS C:\> Stop-Transcript
    Transcript stopped, output file is C:\Users\student\Desktop\transcript.log
```
Note

The PowerShell transcript also logs the output of any commands that were run by the user that initiated the transcript.

### Script Block Logging

The next type of PowerShell logging we will explore is script block logging. Any time a PowerShell command or script is run with a script block, if script block logging is enabled, it will be logged to a Windows Event Log.

   - Open the Group Policy Editor from the Start Menu gpedit.msc

       - Navigate to "Computer Configuration" > "Administrative Templates" > "Windows Components" > "Windows PowerShell"

       - Click on "Turn on PowerShell Script Block Logging"

       - Click on the highlighted Edit "policy setting"

       - Click on the "Enabled" radio button, click "Apply" and then "OK"

**Verifying Script Block Logging is enabled: You will need to run a few commands to verify that logging is enabled after making the change in group policy. Copy and Paste the following commands..**
```
PS C:\> $ScriptBlockLoggingEnabled = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
PS C:\> if ($ScriptBlockLoggingEnabled -and $ScriptBlockLoggingEnabled.EnableScriptBlockLogging -eq 1) {
                Write-Host "Script Block Logging is Enabled."
        } else {
                Write-Host "Script Block Logging is not Enabled."
        }
    Script Block Logging is Enabled.
```
### Windows Event Logging

The final logging solution we will discuss for PowerShell is Windows Event Logs. Windows Event Logs provide a wealth of valuable knowledge for analysts to determine what actions have occurred on a Windows device.

**Checking the Windows PowerShell Windows Event Log in PowerShell: These logs can be viewed by running the following command..**
```
PS C:\> Get-WinEvent -LogName 'Windows PowerShell'
    TimeCreated                     Id LevelDisplayName Message
    -----------                     -- ---------------- -------
    1/4/2024 11:18:16 AM           403 Information      Engine state is changed from Available to Stopped. …
    1/4/2024 11:17:34 AM           400 Information      Engine state is changed from None to Available. …
    1/4/2024 11:17:34 AM           600 Information      Provider "Variable" is Started. …
    1/4/2024 11:17:34 AM           600 Information      Provider "Function" is Started. …
    1/4/2024 11:17:34 AM           600 Information      Provider "FileSystem" is Started. …
    1/4/2024 11:17:34 AM           600 Information      Provider "Environment" is Started. …
```
**Checking script block logs in PowerShell 5.1: We use the -MaxEvents 10 parameter to avoid seeing too many unnecessary results. You should see the commands we ran previously to check if script block logging was enabled..**
```
PS C:\> $scriptBlockLogs = Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath "*[System[(EventID=4104)]]" -MaxEvents 10
PS C:\> foreach ($logEntry in $scriptBlockLogs) {
            $logEntry.Message
            Write-Host "----------------------"
        }
    ----------------------
    Creating Scriptblock text (1 of 1):
    if ($ScriptBlockLoggingEnabled -and $ScriptBlockLoggingEnabled.EnableScriptBlockLogging -eq 1) {Write-Host "Script block logging is enabled."} else {Write-Host "Script block logging is not enabled."}

    ScriptBlock ID: a3f822fb-f3d7-4fe8-859c-c2f3537a5b80
    Path:
    ----------------------
```
**Checking script block logs in PowerShell 7.*.**
```
PS C:\> $scriptBlockLogs = Get-WinEvent -LogName 'PowerShellCore/Operational' -FilterXPath "*[System[(EventID=4104)]]" -MaxEvents 10
PS C:\> foreach ($logEntry in $scriptBlockLogs) {
            $logEntry.Message
            Write-Host "----------------------"
        }
    ----------------------
    Creating Scriptblock text (1 of 1):
    if ($ScriptBlockLoggingEnabled -and $ScriptBlockLoggingEnabled.EnableScriptBlockLogging -eq 1) {
                Write-Host "Script Block Logging is Enabled."
            } else {
                Write-Host "Script Block Logging is not Enabled."
            }

    ScriptBlock ID: 4a3e1a96-bfea-40a5-bc6c-442d3222f075
    Path:
    ----------------------
```
# PowerShell Remoting (PS Remoting)

PowerShell remoting is a very powerful tool at an administrator’s and an analyst’s disposal. However, if not configured properly, PSRemoting can create a large vulnerability for an attacker to live off the land. It is very important to know what good security configurations look like and how to implement them if they don’t exist.

## Windows Remote Management (WinRM)¶

WinRM is another Windows component that uses the WS-Management protocol (WSMan). WinRM is intended for use by remote management IT professionals who use scripts to automate the management of clients and servers remotely. However, it is also a very useful tool for Cyber Analysts if they are provided with access to use it.

WinRM has to be enabled on a host-by-host basis either manually or via group policy object (GPO) implementation. Working with servers and computers with WinRM enabled and configured will allow PSRemoting to take place.

### Setting up WinRM using GPO

If you have the required access to do so, setting up WinRM via GPO is the more efficient method of doing so. Becoming familiar with the process of deploying group policy is a useful skill to know. However, demonstrating deployment of WinRM via GPO is outside the scope of this course.

To learn more about WinRM, you can read about it [here](https://learn.microsoft.com/en-us/windows/win32/winrm/portal)

If you want to learn about configuring WinRM via GPO, please read more about it [here](https://support.auvik.com/hc/en-us/articles/204424994-How-to-enable-WinRM-with-domain-controller-Group-Policy-for-WMI-monitoring)

### Setting up WinRM manually using PowerShell

We did not demonstrate GPO deployment for WinRM, but we will demonstrate manual configuration using PowerShell.

**Configuring and Testing WinRM and PSRemoting using PowerShell.** 
```
# Enable PSRemoting and skip the network profile check to avoid errors
PS C:\> Enable-PSRemoting -SkipNetworkProfileCheck -Force
    WinRM is already set up to receive requests on this computer.
    WinRM has been updated for remote management.
    WinRM firewall exception enabled.

# Check trusted hosts file
PS C:\> Get-Item WSMan:\localhost\client\TrustedHosts

        WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Client

    Type            Name                           SourceOfValue   Value
    ----            ----                           -------------   -----
    System.String   TrustedHosts

# Set trusted hosts to allow your connection to a desired host or hosts. Multiple trusted hosts can be created in a comma separated list and stored in a variable for use with this command
# Enter "Y" when prompted
PS C:\> Set-Item WSMan:\localhost\Client\TrustedHosts -Value 10.50.22.95

    WinRM Security Configuration.
    This command modifies the TrustedHosts list for the WinRM client. The computers in the TrustedHosts list might not be authenticated. The client might send
    credential information to these computers. Are you sure that you want to modify this list?
    [Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y

# Check the trusted hosts file again to verify the change
PS C:\> Get-item WSMan:\localhost\Client\TrustedHosts

        WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Client

    Type            Name                           SourceOfValue   Value
    ----            ----                           -------------   -----
    System.String   TrustedHosts                                   10.50.22.95
```
**Warning**
Setting the WSMan:\localhost\Client\TrustedHosts Value to * will enable you to connect to ANY machine. However, this will also allow you to trust connections FROM any machine, thus bypassing ALL Windows security features!

## Enter-PSSession

Using the Enter-PSSession cmdlet, you can enter an interactive PowerShell session with a remote host. This is a useful tool for performing analysis on a remote host without logging directly into the host, potentially exposing your credentials or storing a logon token.

When entering a PSSession, if your current user account is allowed to connect to the remote host, you will not have to provide credentials, showcased by the example in the previous section. However, if you want to authenticate to a different account with more or different permissions, you will need to provide credentials. It is a best practice to store the credentials as opposed to typing them into the command.

**Entering a remote PowerShell Session using stored credentials.** 
```
# Verify that your WSMAN changes worked by establishing a remote session to the trusted host
PS C:\> Enter-PSSession -ComputerName 10.50.22.95 -Credential Administrator
    [10.50.22.95]: PS C:\Users\Administrator\Documents>

# type exit to terminate the remote session
[10.50.22.95]: PS C:\Users\Administrator\Documents> exit
    PS C:\>

# Typing this command will cause a prompt to pop-up requesting a username and password which will be stored as a secure string in the variable
PS C:\> $Creds = Get-Credential

    PowerShell credential request
    Enter your credentials.
    User: Administrator
    Password for user Administrator: *************

PS C:\> $Creds

    UserName                                 Password
    --------                                 --------
    Administrator                            System.Security.SecureString

PS C:\> Enter-PSSession -ComputerName 10.50.22.95 -Credential $Creds

    [10.50.22.95]: PS C:\Users\Administrator\Documents>
```
**Retrieving useful information from a remote host during an interactive PowerShell session.**
```
# From your remote PowerShell Session, you can run PowerShell cmdlets just like if you were physically using the host
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-Process | Select-Object -First 10

    Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
    -------  ------    -----      -----     ------     --  -- -----------
        88       6      912       4656       0.02   3956   0 AggregatorHost
        229      14    11104      11396       4.73   7156   2 conhost
        483      20     1868       6208       1.36    444   0 csrss
        462      17     2116      21232       3.22   1740   2 csrss
        162      11     1740       6060       0.05   2912   3 csrss
        423      16     4124      21260       1.91   1684   2 ctfmon
        409      34    24696      31672      62.00   3208   0 dfsrs
        204      14     2496       8764       3.06   3500   0 dfssvc
        240      17     3924      12880       0.22   6708   2 dllhost
        10510    7511   250364     242556      42.27   2908   0 dns

# Viewing network connection information for the remote host, showcasing the established connection over port 5985 (WinRM) from our local client to the remote server.
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-NetTCPConnection | Select-Object -Property LocalAddress,RemoteAddress,LocalPort,OwningProcess,State | Where-Object {$_.State -eq "Established" -and $_.LocalPort -eq '5985'}

    LocalAddress  : 10.50.22.95
    RemoteAddress : 10.50.33.11
    LocalPort     : 5985
    OwningProcess : 4
    State         : Established

    LocalAddress  : 10.50.22.95
    RemoteAddress : 10.50.33.11
    LocalPort     : 5985
    OwningProcess : 4
    State         : Established

    LocalAddress  : 10.50.22.95
    RemoteAddress : 10.50.33.11
    LocalPort     : 5985
    OwningProcess : 4
    State         : Established

# Querying Windows event logs on a remote computer to see successful logon attempts with partial output
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-WinEvent -Logname Security -MaxEvents 5 | Select-Object -Property Logname,Id,Message | Where-Object {$_.ID -eq '4624'} | format-list

    LogName : Security
    Id      : 4624
    Message : An account was successfully logged on.

            Subject:
                    Security ID:            S-1-0-0
                    Account Name:           -
                    Account Domain:         -
                    Logon ID:               0x0

            Logon Information:
                    Logon Type:             3
                    Restricted Admin Mode:  -
                    Virtual Account:                No
                    Elevated Token:         Yes

            Impersonation Level:          Impersonation

            New Logon:
                    Security ID:            S-1-5-18
                    Account Name:           POWERSHELL-PEDC$
                    Account Domain:         PSPE.MIL
                    Logon ID:               0x29CCF98
                    Linked Logon ID:                0x0
                    Network Account Name:   -
                    Network Account Domain: -
                    Logon GUID:             {1ec03e8e-456a-d587-54ad-132247c51a40}

# Querying Windows PowerShell operational logs on a remote computer (PowerShell 5.1)
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-WinEvent -Logname Microsoft-Windows-PowerShell/Operational -MaxEvents 5 | Select-Object -Property TimeCreated,LevelDisplayName,Message

    TimeCreated          LevelDisplayName Message
    -----------          ---------------- -------
    1/24/2024 3:46:47 PM Warning          Creating Scriptblock text (1 of 1):...
    1/24/2024 3:46:47 PM Warning          Creating Scriptblock text (1 of 1):...
    1/24/2024 3:46:47 PM Warning          Creating Scriptblock text (3 of 3):...

# Querying Windows PowerShell operational logs on a remote computer (PowerShell 7)
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-WinEvent -Logname PowerShellCore/Operational -MaxEvents 5 | Select-Object -Property TimeCreated,LevelDisplayName,Message

    TimeCreated           LevelDisplayName Message
    -----------           ---------------- -------
    11/27/2024 7:10:49 AM Warning          Creating Scriptblock text (6 of 6):...
    11/27/2024 7:10:49 AM Warning          Creating Scriptblock text (5 of 6):...
    11/27/2024 7:10:49 AM Warning          Creating Scriptblock text (4 of 6):...
    11/27/2024 7:10:49 AM Warning          Creating Scriptblock text (3 of 6):...
    11/27/2024 7:10:49 AM Warning          Creating Scriptblock text (2 of 6):...

# Querying Windows event logs on a remote computer, filtering for a specific event ID, a specific string, and formatting as a text wrapped table.
[10.50.22.95]: PS C:\Users\Administrator\Documents> Get-Winevent -logname Security | Where-Object {$_.ID -eq '4624' -and $_.message -match "success"} | Select-Object -First 1 | ft -wrap


   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
12/3/2024 3:50:47 PM          4624 Information      An account was successfully logged on.

                                                    Subject:
                                                        Security ID:            S-1-0-0                                                                                                                                       
                                                        Account Name:           -                                                                                                                                             
                                                        Account Domain:         -                                                                                                                                             
                                                        Logon ID:               0x0                                                                                                                                           

                                                    Logon Information:
                                                        Logon Type:             3                                                                                                                                             
                                                        Restricted Admin Mode:  -                                                                                                                                             
                                                        Virtual Account:                No                                                                                                                                    
                                                        Elevated Token:         Yes                                                                                                                                           

                                                    Impersonation Level:                Impersonation                                                                                                                         

                                                    New Logon:
                                                        Security ID:            S-1-5-18                                                                                                                                      
                                                        Account Name:           POWERSHELL-PEDC$                                                                                                                              
                                                        Account Domain:         PSPE.MIL                                                                                                                                      
                                                        Logon ID:               0xB5BECE4                                                                                                                                     
                                                        Linked Logon ID:                0x0                                                                                                                                   
                                                        Network Account Name:   -                                                                                                                                             
                                                        Network Account Domain: -                                                                                                                                             
                                                        Logon GUID:             {765d4bd6-603d-2c63-5649-bed5ea0587d6}                                                                                                        

                                                    Process Information:
                                                        Process ID:             0x0                                                                                                                                           
                                                        Process Name:           -                                                                                                                                             

                                                    Network Information:
                                                        Workstation Name:       -                                                                                                                                             
                                                        Source Network Address: ::1                                                                                                                                           
                                                        Source Port:            60715                                                                                                                                         

                                                    Detailed Authentication Information:
                                                        Logon Process:          Kerberos                                                                                                                                      
                                                        Authentication Package: Kerberos                                                                                                                                      
                                                        Transited Services:     -                                                                                                                                             
                                                        Package Name (NTLM only):       -                                                                                                                                     
                                                        Key Length:             0                                                                                                                                             

                                                    This event is generated when a logon session is created. It is generated on the computer that was accessed.

                                                    The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process
                                                    such as Winlogon.exe or Services.exe.

                                                    The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

                                                    The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

                                                    The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

                                                    The impersonation level field indicates the extent to which a process in the logon session can impersonate.

                                                    The authentication information fields provide detailed information about this specific logon request.
                                                        - Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.                                                                        
                                                        - Transited services indicate which intermediate services have participated in this logon request.                                                                    
                                                        - Package name indicates which sub-protocol was used among the NTLM protocols.                                                                                        
                                                        - Key length indicates the length of the generated session key. This will be 0 if no session key was requested.


# Querying Kerberos information in a remote PowerShell session
PS C:\Users\student\Desktop> Enter-PSSession -ComputerName 10.50.22.95 -Credential $Creds

# Run the following command making use of the GetCurrent() method of the WindowsIdentity Class in the .NET framework to display Kerberos information
[10.50.22.95]: PS C:\Users\Administrator\Documents> [System.Security.Principal.WIndowsIdentity]::GetCurrent()

    AuthenticationType : Kerberos
    ImpersonationLevel : None
    IsAuthenticated    : True
    IsGuest            : False
    IsSystem           : False
    IsAnonymous        : False
    Name               : PSPE\Administrator
    Owner              : S-1-5-32-544
    User               : S-1-5-21-3266719963-742974059-281163612-500
    Groups             : {S-1-5-21-3266719963-742974059-281163612-513, S-1-1-0, S-1-5-32-544, S-1-5-32-545...}
    Token              : 1292
    AccessToken        : Microsoft.Win32.SafeHandles.SafeAccessTokenHandle
    UserClaims         : {http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name: PSPE\Administrator,
                        http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid:
                        S-1-5-21-3266719963-742974059-281163612-500,
                        http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid:
                        S-1-5-21-3266719963-742974059-281163612-513,
                        http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid:
                        S-1-5-21-3266719963-742974059-281163612-513...}
    DeviceClaims       : {}
    Claims             : {http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name: PSPE\Administrator,
                        http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid:
                        S-1-5-21-3266719963-742974059-281163612-500,
                        http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid:
                        S-1-5-21-3266719963-742974059-281163612-513,
                        http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid:
                        S-1-5-21-3266719963-742974059-281163612-513...}
    Actor              :
    BootstrapContext   :
    Label              :
    NameClaimType      : http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name
    RoleClaimType      : http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid
```
**Warning**
Do not run the above Kerberos commands on a customer’s network unless they give you explicit permission to do so.

**Note**
To display the full message for event logs, use the Format-List cmdlet and -wrap switch parameter. Remember to use exclusion statements and sorting to limit the amount of results. Log messages contain a lot of information and just a couple of logs will fill your entire PowerShell window.

PowerShell allows for running commands on remote computers as well as connecting to remote machines.

