# Execution Policies

PowerShell sessions use a safety feature called execution policies. There are several levels of execution policy that determine what type and to what extent scripts can be executed on a host. By default, PowerShell uses the Restricted execution policy which will prevent all PowerShell scripts from running unless it is changed. Below are some examples of the behavior you can expect from the different execution policies.

**PowerShell execution policies and associated parameters.**
```
PS C:\> Get-ExecutionPolicy
    Restricted

# View all execution policies on the current host
PS C:\> Get-ExecutionPolicy -List

        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process       Undefined
  CurrentUser       Undefined
 LocalMachine    Unrestricted

# Set and test different execution policies
# *AllSigned* will require that all scripts run on the host be signed by a trusted publisher.  The script will simply not run in PowerShell 7. We get an error when trying to run a script
# previously created on the host if using PowerShell 5.

PS C:\Users\defender\Desktop\Scripts> Set-ExecutionPolicy AllSigned

PS C:\Users\defender\Desktop\Scripts> .\ExecutionPolicyDemo.ps1

PS C:\Users\defender\Desktop\Scripts> powershell
    Windows PowerShell
    Copyright (C) Microsoft Corporation. All rights reserved.

    Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\defender\Desktop\Scripts> .\ExecutionPolicyDemo.ps1
    .\ExecutionPolicyDemo.ps1 : File C:\Users\defender\Desktop\Scripts\ExecutionPolicyDemo.ps1 cannot be loaded because running scripts is disabled on this system. For more information,
    see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
    At line:1 char:1
    + .\ExecutionPolicyDemo.ps1
    + ~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : SecurityError: (:) [], PSSecurityException
        + FullyQualifiedErrorId : UnauthorizedAccess

# *RemoteSigned* will allow scripts with trusted digital signatures from the internet and any scripts written on the local host to run. RemoteSigned is the default setting on Windows Servers.
# After downloading a script from the internet, attempting to run it with the execution policy RemoteSigned enabled will result in a prompt asking if you trust the script and want to run it.
PS C:\Users\defender\Desktop\Scripts> Set-ExecutionPolicy RemoteSigned

PS C:\Users\defender\Desktop\Scripts> .\ExecutionPolicyDemo.ps1

    Name
    ----
    powershell_ise

# *Restricted* will prevent any scripts from running on the host. In PowerShell 7, the script will not run. In PowerShell 5, the script will not run, and we will see an error.

PS C:\Users\defender\Desktop\Scripts> Set-ExecutionPolicy Restricted

PS C:\Users\defender\Desktop\Scripts> .\ExecutionPolicyDemo.ps1

PS C:\Users\defender\Desktop\Scripts> powershell

    Windows PowerShell
    Copyright (C) Microsoft Corporation. All rights reserved.

    Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\defender\Desktop\Scripts> .\ExecutionPolicyDemo.ps1

    .\ExecutionPolicyDemo.ps1 : File C:\Users\defender\Desktop\Scripts\ExecutionPolicyDemo.ps1 cannot be loaded because running scripts is disabled on this system. For more information,
    see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
    At line:1 char:1
    + .\ExecutionPolicyDemo.ps1
    + ~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : SecurityError: (:) [], PSSecurityException
        + FullyQualifiedErrorId : UnauthorizedAccess

# *Unrestricted* will allow all scripts to run and will prompt the user if the script originated outside the local internet zone. This is the default setting and cannot be changed on
# non-Windows devices running PowerShell.
# The results are the same between PowerShell 5 and 7

PS C:\Users\defender\Desktop\Scripts> Set-ExecutionPolicy Unrestricted

PS C:\Users\defender\Desktop\Scripts> .\ExecutionPolicyDemo.ps1

    Name
    ----
    powershell_ise

PS C:\Users\defender\Desktop\Scripts> powershell

    Windows PowerShell
    Copyright (C) Microsoft Corporation. All rights reserved.

    Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\defender\Desktop\Scripts> .\ExecutionPolicyDemo.ps1

    Name
    ----
    powershell
    powershell_ise

# *Bypass* will allow all scripts to run and will not warn the user if the script is potentially malicious, use with caution.
PS C:\Users\defender\Desktop\Scripts> Set-ExecutionPolicy Bypass

PS C:\Users\defender\Desktop\Scripts> .\ExecutionPolicyDemo.ps1

    Name
    ----
    powershell_ise
```

**Warning**

If you ever set the PowerShell execution policy to bypass within a script, ensure to set the policy back to the original value after the script finishes. Unlike most commands, execution policy settings persist even after closing a PowerShell session.


# Error Handling

Error handling is important when creating PowerShell scripts. A script that runs correctly once may not run correctly every time. A terminating error stops a statement from running; also referred to as exceptions in other languages. There are a few methods for error handling, we’ll cover the following:

   - Try, Catch, Finally

       - Try - Defines a section of a script to monitor for errors

       - Catch - Can have multiple catch blocks to match errors

       - Finally - Will always run, whether the code fails or succeeds during execution

**Using Try, Catch, Finally.**
```
# Spelling and formatting errors can be common in larger script blocks, but other issues unrelated to user error can generate errors. The below example showcases an access restriction error.
PS C:\> Try {
            Get-ChildItem "c:\windows\system32\com\dmp"
        }
        Catch [System.UnauthorizedAccessException] {
            Write-Host "You don't have access to the file" -ForegroundColor Red
        }
        Catch {
            Write-Host "Something else weird happened" -ForegroundColor Yellow
        }
        Finally {
            Write-Host "Regardless of whether or not there was an error, we still execute this" -ForegroundColor Green
        }

# PRODUCE_ERROR will cause an error during code execution because it is not a valid computer name, but it will still return the BIOS Name property since we specify -ErrorAction Continue
# and the computer name for localhost is a valid property value for the Get-CimInstance Win32_BIOS -ComputerName parameter.

PS C:\> Try {
            $BiosName = (Get-CimInstance Win32_BIOS -ComputerName localhost,PRODUCE_ERROR -ErrorAction Continue).Name
            Write-Host $BiosName -ForegroundColor Green
        }
        Catch [System.Management.Automation.CommandNotFoundException] {
            Write-Host "CATCH 1: The command is not found!" -ForegroundColor Red
        }
        Catch {
            Write-Host "CATCH 2: This is a catch all by default" -ForegroundColor Yellow
        }
        Finally {
            Write-Host "FINALLY: Runs no matter what..." -ForegroundColor Green
        }

    Get-CimInstance : The WinRM client cannot process the request. If the authentication scheme is different from Kerberos, or if the client computer is not
    joined to a domain, then HTTPS transport must be used, or the destination machine must be added to the TrustedHosts configuration setting. Use winrm.cmd to
    configure TrustedHosts. Note that computers in the TrustedHosts list might not be authenticated. You can get more information about that by running the
    following command: winrm help config.
    At line:2 char:25
    + ... BiosName = (Get-CimInstance Win32_BIOS -ComputerName localhost,PRODUC ...
    +                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : NotEnabled: (root\cimv2:Win32_BIOS:String) [Get-CimInstance], CimException
        + FullyQualifiedErrorId : HRESULT 0x803380e4,Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand
        + PSComputerName        : PRODUCE_ERROR

    Default System BIOS
    FINALLY: Runs no matter what...

# If we want to see the output without the error, we can use -ErrorAction SilentlyContinue
PS C:\> Try {
            $BiosName = (Get-CimInstance Win32_BIOS -ComputerName localhost,PRODUCE_ERROR -ErrorAction SilentlyContinue).Name
            Write-Host $BiosName -ForegroundColor Green
        }
        Catch [System.Management.Automation.CommandNotFoundException] {
            Write-Host "CATCH 1: The command is not found!" -ForegroundColor Red
        }
        Catch {
            Write-Host "CATCH 2: This is a catch all by default" -ForegroundColor Yellow
        }
        Finally {
            Write-Host "FINALLY: Runs no matter what..." -ForegroundColor Yellow
        }

    Default System BIOS
    FINALLY: Runs no matter what...
```
## Trap Statements

   - Trap Statement

       - The Trap statement can also be used to handle terminating errors in scripts

       - The Trap keyword specifies statements to run when a terminating error occurs

       - Trap statements handle the terminating errors and allow execution to continue

       - Continue can be used with Trap statements to prevent the error message from being displayed

**Using a Trap Statement function.**
```
# Get-Process is misspelled as Get-Processes and will cause an error at execution, the Trap Statement will trap the error and allow the remaining code to run successfully
PS C:\> Function Trap-Test {
            Trap [System.Management.Automation.CommandNotFoundException] {
                Write-Host "TRAP ERROR: The command is not found, check your spelling!" -ForegroundColor Red
                continue
            }
            Trap {
                Write-Host "TRAP ERROR: This is a catch all by default" -ForegroundColor Yellow
            }
            Get-Processes
            $BiosName = (Get-CimInstance Win32_BIOS -ComputerName localhost).Name
            Write-Host "Bios Name: $BiosName" -ForegroundColor Green
            }

PS C:\> Trap-Test

    TRAP ERROR: The command is not found, check your spelling!
    Bios Name: 1301

Error Reporting
---------------

-   Another part of error handling in PowerShell is error reporting.

    -   Errors that occur during a PowerShell session are stored in the
        `$Error` and `$LastExitCode` variables and can be queried at any
        time to determine the cause of the errors.

    -   Particularly useful when running large scripts that may generate
        several errors that you do not get the chance to read as they
        scroll by in the window.

    -   Additionally, stores errors even if your `ErrorAction`
        preference is `SilentlyContinue` which we will discuss in the
        next section.

**Observing the contents of the $Error and $LastExitCode variables.**
```powershell
PS C:\> Get-Processes

    Get-Processes : The term 'Get-Processes' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the
    name, or if a path was included, verify that the path is correct and try again.
    At line:2 char:1
    + Get-Processes
    + ~~~~~~~~~~~~~
        + CategoryInfo          : ObjectNotFound: (Get-Processes:String) [], CommandNotFoundException
        + FullyQualifiedErrorId : CommandNotFoundException

# Using the $Error variable, we can see the error we just caused
PS C:\> $Error | Select-Object -First 1

    Get-Processes : The term 'Get-Processes' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the
    name, or if a path was included, verify that the path is correct and try again.
    At line:2 char:1
    + Get-Processes
    + ~~~~~~~~~~~~~
        + CategoryInfo          : ObjectNotFound: (Get-Processes:String) [], CommandNotFoundException
        + FullyQualifiedErrorId : CommandNotFoundException

# Using the $LastExitCode variable. This will cause cmd.exe to open and if it is closed normally, it will return an exit code of 0. If any other number is returned, something failed.
PS C:\> $process = Start-Process -FilePath "C:\Windows\System32\cmd.exe" -PassThru
        $process.WaitForExit()

        $exitCode = $process.ExitCode

        Write-Host "Exit Code: $exitCode"

        if ($exitCode -eq 0) {
            Write-Host "Command executed successfully."
        } else {
            Write-Host "Error: Something went wrong with the process."
        }

    Exit Code: 0
    Command executed successfully.

# Using the $LastExitCode variable. This will cause PowerShell.exe to run the incorrectly spelled Get-Processes command which will result in an exit code of 1 as the process will not run successfully.
PS C:\> PowerShell.exe Get-Processes

        $exitCode = $LastExitCode

        Write-Host "Exit Code: $exitCode"

        if ($exitCode -eq 0) {
            Write-Host "Command executed successfully."
        } else {
            Write-Host "Error: Something went wrong with the command."
        }

    Exit Code: 1
    Error: Something went wrong with the command.
```

   - ErrorAction

       - Error Action can be set per command or universally

           - Per Command
```
# Will work as intended
PS C:\> Get-Process -ErrorAction SilentlyContinue

# Will not work because Get-Processes is not a recognized cmdlet with the -ErrorAction parameter
PS C:\> Get-Processes -ErrorAction SilentlyContinue
    Get-Processes: The term 'Get-Processes' is not recognized as a name of a cmdlet, function, script file, or executable program.
    Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
```
**Globally set ErrorAction preference to "SilentlyContinue" for the current session.**
```
$ErrorActionPreference = "SilentlyContinue"
```
   - Different `ErrorActionPreference` options and their functions

       - **Break**: Enter the debugger when an error occurs or when an exception is raised.

       - **Continue**: (Default) Displays the error message and continues executing.

       - **Ignore**: Suppresses the error message and continues to execute the command. The Ignore value is intended for per-command use, not for use as saved preference. Ignore isn’t a valid value for the $ErrorActionPreference variable.

       - **Inquire**: Displays the error message and asks you whether you want to continue.

       - **SilentlyContinue**: No effect. The error message isn’t displayed, and execution continues without interruption.

       - **Stop**: Displays the error message and stops executing. In addition to the error generated, the Stop value generates an ActionPreferenceStopException object to the error stream.

       - **Suspend**: Automatically suspends a workflow job to allow for further investigation. After investigation, the workflow can be resumed. The Suspend value is intended for per-command use, not for use as saved preference. Suspend isn’t a valid value for the $ErrorActionPreference variable.

# Script Structure

PowerShell scripts follow a simple structure, but don’t **need** to have any sort of structure depending on what you want the script to do. A PowerShell script can be as simple as running two cmdlets with custom output. They can also include more complexity, such as custom parameters and functions. Below is an example of a standard PowerShell script with custom parameters and functions. While there is no industry standard for PowerShell script structure, it is considered best practice to avoid using aliases, comment your code, and perform error handling in your scripts.

Using PowerShell ISE, copy and paste the following script to test on your local machine. 
```
# Script Name: ProcessesAndNetwork.ps1
# Description: This script uses several of the concepts learned in this course to display processes or network connections to the user.

function Show-ProcessesOrNetwork {

    # Parameters to store the process name or port number supplied by the user at run time
    param (
        [string]$ProcessName,
        [int]$PortNumber
    )

    $continue = $true

    # While loop to run the script until the user enters the choice to exit or presses Ctrl + C
    while ($continue) {
        Write-Host "Choose an option:"
        Write-Host "1. Show Running Processes"
        Write-Host "2. Show Network Connections"
        Write-Host "3. Show Processes by Name"
        Write-Host "4. Show Network Connections by Port"
        Write-Host "5. Exit"

        $choice = Read-Host "Enter 1, 2, 3, 4, or 5"

        # Switch construct that provides the user with different outcomes based on their choice
        switch ($choice) {
            1 {
                Write-Host "Running Processes:"
                Get-Process
                break
            }
            2 {
                Write-Host "Network Connections:"
                Get-NetTCPConnection
                break
            }
            3 { # Prompt the user for a Process Name to search for with the Get-Process cmdlet
                if (-not $ProcessName) {
                    $ProcessName = Read-Host "Enter the name of the process to search for"
                }
                Write-Host "Processes matching '$ProcessName':"
                Get-Process -Name $ProcessName

                # Resets the process name to an empty string so the user can enter a new one
                $ProcessName = ""
                break
            }
            4 { # Prompt the user for a port number to search for with the Get-NetTCPConnection cmdlet
                if (-not $PortNumber) {
                    $PortNumber = Read-Host "Enter the network port to search for"
                }
                Write-Host "Network Connections on port:"$PortNumber
                Get-NetTCPConnection | Where-Object { $_.LocalPort -eq $PortNumber -or $_.RemotePort -eq $PortNumber } | Format-List

                # Resets the port number to an empty string so the user can enter a new one
                $PortNumber = ""
                break
            }
            5 {
                Write-Host "Exiting..."
                $continue = $false
                break
            }
            default {
                Write-Host "Invalid choice. Please enter 1, 2, 3, 4, or 5. Try again."
            }
        }
    }
}

Show-ProcessesOrNetwork
```
## Script Repurposing

Now that we have created a good script for performing a couple of actions on a local host, let’s repurpose that script to use on remote hosts. If you have working logic developed, do not re-invent the wheel. Save yourself time and effort by repurposing existing scripts that you know will work. As you add more functionality to an existing script you will have to step through it and debug any errors or unexpected results you encounter.

Using PowerShell ISE, copy and paste the repurposed script and compare it to the previous script to see how it changed.

**Repurposed ProcessesAndNetwork.ps1.**
```
# Script Name: ProcessesAndNetworkRemote.ps1
<# Description: This script uses several of the concepts learned in this course to display processes or network connections to the user on the local host.
It is a repurposed version of ProcessesAndNetwork.ps1 script that includes remote functionality and some event handling using more concepts learned during this course. #>

function Show-ProcessesOrNetwork {

    # Gets domain credentials for PSRemoting
    $Creds = Get-Credential
    # Stores the current value of your trusted hosts file for later use.
    $WSMan = Get-Item WSMan:\localhost\Client\TrustedHosts | Select-Object Value
    # Allow your host to connect to multiple hosts using PSRemoting.
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force

    # Stores user provided IP addresses into a variable, splits them on the comma, and gets each unique IP and stores them in a separate variable.
    $IPAddresses = Read-Host "Enter one or more IP addresses (separated by commas)"
    $IPAddresses = $IPAddresses -split ','
    $UniqueIPs = $IPAddresses | Get-Unique

    # Event handler in the case CTRL+C is pressed during run time using a Try/Finally construct.
    Try {

        # Ensures the script will continue to run after each selection is made until option 5 is chosen or Ctrl+C is sent.
        $continue = $true

        # While Loop that will continue as long as the $continue variable resolves to $true.
        while ($continue) {
            Write-Host "Choose an option:`n1. Show Running Processes`n2. Show Network Connections`n3. Show Processes by Name`n4. Show Established Network Connections by Port`n5. Exit"

            # Reads user input for their selection.
            $choice = Read-Host "Enter 1, 2, 3, 4, or 5"

            # Switch construct that provides the user with different outcomes based on their choice
            switch ($choice) {
                1 { # Foreach Loop that Checks a remote computer or computers for all running processes.
                    foreach ($IP in $UniqueIPs) {
                        $result = Invoke-Command -ComputerName $IP -ScriptBlock {Get-Process | Select-Object -Property ProcessName,ID,Path | Format-Table} -Credential $Creds -ErrorAction SilentlyContinue

                        if ($result) {
                            Write-Host "Showing Processes Running on ""$IP"":"`n
                            $result | ForEach-Object { $_ }
                        }
                    }
                    break
                }
                2 { # Foreach Loop that Checks a remote computer or computers for network connections.
                    foreach ($IP in $UniqueIPs) {
                        $result = Invoke-Command -ComputerName $IP -ScriptBlock {
                            Get-NetTCPConnection |
                            Select-Object -Property LocalAddress,RemoteAddress,State,LocalPort,RemotePort |
                            Where-Object {
                                $_.LocalAddress -ne "0.0.0.0" -and $_.LocalAddress -ne "::" -and $_.LocalAddress -notlike "fe*" -and
                                $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -notlike "::*" -and $_.RemoteAddress -notlike "fe*"
                            } |
                            Format-Table
                        } -Credential $Creds -ErrorAction SilentlyContinue

                        if ($result) {
                            Write-Host "Showing Network Connections on ""$IP"":" `n
                            $result | ForEach-Object { $_ }
                        }
                    }
                    break
                }
                3 { # If statement to check that the ProcessName parameter is empty and if it is, it asks the user to provide a process name.
                    if (-not $ProcessName) {
                        $ProcessName = Read-Host "Enter the name of the process to search for"
                    }

                    # Foreach Loop that Checks a remote computer or computers for running processes that match the user provided input.
                    foreach ($IP in $UniqueIPs) {
                        $result = Invoke-Command -ComputerName $IP -ScriptBlock {
                            param($ProcessName)
                            Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -Property ProcessName, ID, Path
                        } -ArgumentList $ProcessName -Credential $Creds

                        if ($result) {
                            Write-Host "$ProcessName is Running on ""$IP""" `n
                            $result | Select-Object -Property PSComputerName,ProcessName, ID, Path | Format-Table
                        } else {
                            Write-Host "$ProcessName is not Running on ""$IP""" `n
                        }

                        $ProcessName = ""
                    }

                    break
                    }
                    4 { # If statement to check that the PortNumber parameter is empty and if it is, it asks the user to provide a port number.
                    if (-not $PortNumber) {
                        $PortNumber = Read-Host "Enter the network port to search for"
                    }

                    # Foreach Loop that Checks a remote computer or computers for established connections on a port provided by the user.
                    foreach ($IP in $UniqueIPs) {
                        $result =  Invoke-Command -ComputerName $IP -Credential $Creds -ScriptBlock {
                            param($PortNumber)
                            Get-NetTCPConnection | Where-Object { $_.LocalPort -eq $PortNumber -and $_.State -eq "established" -or $_.RemotePort -eq $PortNumber -and $_.State -eq "established"  }
                        } -ArgumentList $PortNumber

                        if ($result) {
                            Write-Host "Network Connections on port $PortNumber on ""$IP""" `n
                            $result | Format-List
                        } else {
                            Write-Host "Port $PortNumber not found in any connections on ""$IP""" `n
                        }

                        $PortNumber = ""

                    }

                    break
                }
                5 { # Exit option that will exit the script gracefully.
                    Write-Host "Exiting..."
                    $continue = $false
                    break
                }
                default { # Default option will trigger if any invalid input is provided when the user is selecting a choice.
                    Write-Host "Invalid choice. Please enter 1, 2, 3, 4, or 5. Try again.`n"
                }
            }


        }
    }
    Finally {
        # Return WSMan to its original setting even if a CTRL+C interrupt event takes place.
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $WSMan.Value -Force
    }
}

# Calls the primary function of the script.
Show-ProcessesOrNetwork
```


**Important**

Take note of the commenting that was done in both scripts. It is extremely valuable to comment on your code, that way if you have a long period of time not using PowerShell, or you are sharing it with peers, everyone will be able to understand what is happening.

# Debugging

PowerShell has built-in debugging functionality as well. It can be accomplished using the following cmdlets with your scripts in PowerShell ISE. If you want to debug scripts in PowerShell version 6 or newer, you will need to use debugging with visual studio code (VSCode). VSCode requires that you download a PowerShell extension for it to work.

   - Debugger cmdlets

       - Set-PSBreakpoint: Sets breakpoints on lines, variables, and commands.

       - Get-PSBreakpoint: Gets breakpoints in the current session.

       - Disable-PSBreakpoint: Turns off breakpoints in the current session.

       - Enable-PSBreakpoint: Re-enables breakpoints in the current session.

       - Remove-PSBreakpoint: Deletes breakpoints from the current session.

       - Get-PSCallStack: Displays the current call stack.

To start the debugger, run your script, command, or function with one or more breakpoints set. When the breakpoint is reached, execution will stop, and control is turned over to the debugger. To stop the debugger, continue to run the script, command, or function until it finishes or type `stop` or `t`. We will not demonstrate PowerShell debugging as it is outside the scope of this course.

To learn more about PowerShell debugging, please read about it [here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_debuggers?view=powershell-7.4)

# Offensive and Defensive Tools

PowerShell has a plethora of compatible offensive and defensive toolsets. This section will discuss some of them to provide awareness and some baseline knowledge but will not demonstrate their use as it is outside the scope of this course.

## Offensive Tools

This is not an all-inclusive list, and it may be outdated. If you know of newer offensive tools used with PowerShell, please feel free to share with the class.

   - PowerShell Empire

       - Empire is an older, but common project that is no longer supported. However, still used in the wild.

       - It is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent.

       - Empire is a merger of the previous PowerShell Empire and Python EmPyre projects.

   - PowerSploit

       - PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during an assessment.

       - It is comprised of several modules, offensive in nature, for example ‘Invoke-DllInjection` which is used to inject DLLs into a process ID of the users’ choosing.

   - Nishang
        
       - Nishang is another framework and collection of scripts and payloads that enables the use of PowerShell for its offensive capabilities, red teaming, and penetration testing.

   - PSAttack

       - PSAttack is a portable console designed to make penetration testing with PowerShell easier.

       - It is comprised of over 100 commands for privilege escalation, reconnaissance, and data exfiltration.

   - BloodHound

       - BloodHound is a single page Javascript web application that uses a Neo4j database fed by a C# data collector.

       - It uses graph theory to reveal hidden and often unintended Active Directory or Domain trust relationships.

       - Doubles as a defensive tool when performing vulnerability analysis on the Active Directory and Domain services on a network.

   - Mimikatz

       - Mimikatz is a password and hash dumping tool that abuses a vulnerability in the Windows Lssas process and pulls the desired information from memory.

       - Other tools like PowerSploit come with Mimikatz as a module and is typically called with Invoke-Mimikatz.ps1.

       - Very commonly used by red teams and penetration testers due to its ease of use and high success rate.

## Defensive Tools

As stated earlier, if you know of other commonly used defensive tools, please share with the class.

   - PoSh-EasyWin

       - PoSh-EasyWin is a blue team suite of defense focused PowerShell tools and scripts.

       - It has a slight learning curve, but it is a very effective tool for automating defensive processes on an enterprise network.

       - It can be used to deploy agents across an enterprise, baseline a network, perform vulnerability analysis, support hunt operations, and more.

       - Created by a Warrant Officer with many years of Defensive Cyberspace Operations (DCO) experience and can be found [here](https://github.com/high101bro/PoSh-EasyWin)

   - BloodHound

       - As stated before, BloodHound doubles as a defensive tool and can be used to expose hidden Domain trust relationships, enabled administrator, domain admin, service, enterprise, etc. accounts that should be disabled.

       - It can show current log on sessions from administrations, especially useful when gathering information surrounding a compromise or red team operations.

   - Microsoft Defender Antivirus
       
       - Formerly known as Windows Defender, does a very good job at detecting most malicious activity on a Windows system unless it is misconfigured or disabled.

   - Sysmon

       - Sysmon is a powerful logging tool that runs as a system service and device driver that logs system activity to Windows event logs.

       - It uses its own event IDs and provides more granular information for host analysts to perform analysis from a hunt perspective.

   - Antimalware Scripting Interface (AMSI)

       - Allows a Windows host to inspect the contents of scripts and catches malicious code that might be encoded for obfuscation.

       - AMSI is a useful and powerful built-in Windows feature, but it is vulnerable to bypass if an attacker has administrator credentials on a network.

# PowerShell Mitigations and Evasion

In any computing environment, as an offensive or defensive cyberspace operations technician, it is important to understand ways to evade detection and ways to mitigate risks associated with PowerShell.

Since PowerShell is so commonly used in enterprise environments, it will only benefit you to become knowledgeable on these subjects.

## Mitigations

   - Deploy PowerShell 5.1 or Newer

       - PowerShell 5.1 is built into Windows 10 by default, but it is available on Windows 7 and Windows Server 2008 R2.

       - PowerShell 5.1 is much more secure than previous versions of PowerShell and has better logging capabilities.

   - Script Block Logging and Module Logging
       
       - Just like we discussed on Day 1, logging of PowerShell scripts is important to maintain a secure environment that makes use of PowerShell.

   - Implement JEA

       - We briefly showcased Just Enough Administration on Day 3 in the PowerShell Remoting section.

       - It is a very useful tool to ensure users and administrators are limited to a specific set of cmdlets needed to perform their duties.

   - Deploy Application Control Policies

       - Application control can be used to block PowerShell completely for any user that is not explicitly allowed to use it.

       - Using BeyondTrust can block, or trust based on specific criteria such as blocking command line arguments that could be used for fileless malware attacks running in memory.

   - Upgrade to Windows 10 or Windows Server 2012 at a Minimum
        Windows 7 and Windows Server 2008 have many unresolved vulnerabilities that open up an environment to attack using PowerShell or other offensive tools.

## Evasion

   - Obfuscation

       - This is one of the most common techniques used for defense evasion with PowerShell.

       - It is frequently done by simply base64 encoding script blocks or using in-script XOR encryption.

       - This technique is commonly used to bypass AMSI in Windows environments.

   - Living off the Land (LotL)

       - Many attackers will make use of everything readily available to them, especially if it means they don’t have to risk burning their own tools.

       - This is why it is so important to limit what users have available to them and what administrators can leave on remote hosts.

       - Attackers can make use of artifacts left behind by administrators to propagate through a network.

   - Fileless Attacks

       - Making use of the system memory to run malware and perform actions is an exceptional way to avoid detection.

       - Most environments do not make use of defensive agents that can detect these types of attacks.

   - Use of Alternate Data Streams (ADS)

       - ADS are another useful way to obfuscate offensive actions an attacker is taking on a host.

       - These are fairly easy to detect if the network owner or defense team is knowledgeable on ADS.

   - Disabling Script Block Logging and Module Logging

       - Just like we discussed enabling script block logging on Day 1, an attacker can disable it through the registry.

       - Attackers want to avoid as many detection mechanisms as possible, and with PowerShell script block logging is an important consideration.