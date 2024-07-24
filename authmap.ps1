<#
.DESCRIPTION
    AuthMap is designed to help blue-teamers analyze authentication activity within an Active Directory environment across all enabled computers.

.NOTES
    AuthMap relies on both WMI and SMB being available to launch remote commands as well as to retrieve resultant data.

.LINK
    https://github.com/joeavanzato/authmap

.PARAMETER targetusername
    The username to use when filtering Event Logs - defaults to all users.

.PARAMETER daysback
    How many days backwards to examine Event Logs from the current system time - defaults to 7.

.PARAMETER logontypes
    Specifies which Logon Types to filter on - defaults to all.  Provide as comma-delimited string such as -logontypes 2,3,5,10

.PARAMETER concurrencylimit
    Used when starting remote WMI jobs and when copying data - higher number means additional resource consumption but potentially faster completion (minimally) - defaults to 64.

.EXAMPLES
    .\authmap.ps1 -targetusername 'admin' -daysback 30 -logontypes 10 -> Pull all type 10 logons for past 30 days for user 'admin' from all enabled computers
    .\authmap.ps1 -daysback 7 -logontypes 10,5,3 -> Pull all type 3/510 logons from all enabled computers
#>

param (
[string] $targetusername = '*',
[Int32] $daysback = 7,
[string] $logontypes = "*",
[Int32] $concurrencylimit = 64
)


# This is the actual filter parameter used in xpath - 86400000 represents the number of millisecondsa in a single day
$milliseconds = $daysback * 86400000


# The $settings hashtable is synchronized across all threads and thus accessible to the async jobs and the foreground simultaneously
$settings = [hashtable]::Synchronized(@{})
$settings.hostcount = 0
$settings.reachabledevices = [System.Collections.ArrayList]@()
$settings.launchedjobs = 0

# Get the credentials we should run as - this should be Domain Admin or similar high-priveleged role that can launch remote processes via WMI and access C$ on remote devices via SMB
$credentials = Get-Credential

# Data Storage Paths
$main_storage = "$PSScriptRoot\main"
$device_storage_root = "$PSScriptRoot\devices"
$milli = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$output_file_path = "C:\evtx_hunt_$milli.csv"
$split = $output_file_path.Split("\")

# Log Information
$FilePathToWatch = $PSScriptRoot
$FileNameToWatch = "authmap.log"
$FilePathNameToWatch = Join-Path -Path $FilePathToWatch -ChildPath $FileNameToWatch

# Setup filter string additions involving LogonType
$logontype_filterstring = ""
if (-not ($logontypes -eq "*")){
    $logontype_filterstring += " and "
    $types = $logontypes -split " "
    $idx = 0
    foreach ($t in $types){
        $t = $t.Trim()
        if ($idx -eq 0){
            $logontype_filterstring += "EventData[Data[@Name='LogonType']='$t']"
        } else {
            $logontype_filterstring += " or EventData[Data[@Name='LogonType']='$t']"
        }
        $idx += 1
    }
}

function Log([string]$msg) {
    if ((Test-Path $FilePathNameToWatch -PathType Leaf) -eq $false){
        New-Item $FilePathNameToWatch | Out-Null
    }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $message = "$timestamp :: $msg"
    Add-Content $FilePathNameToWatch $message
    Write-Host $message
}

function CreateStorageDirectories {
    # Creates
    if (-not (Test-Path $main_storage)){
        try {
            New-Item -ItemType Directory -Path $main_storage | Out-Null
        } catch {
            Write-Warning "[!] Could not create critical directory! (main)"
            exit
        }
    }
    if (-not (Test-Path $device_storage_root)){
        try {
            New-Item -ItemType Directory -Path $device_storage_root | Out-Null
        } catch {
            Write-Warning "[!] Could not create critical directory! (devices)"
            exit
        }
    }
}

function GetComputers {
    # Gets all enabled computer accounts from the current AD domain
    # TODO: Allow customhostlist parameter to provide file containing hostnames
    if ($settings.customhostlist){
        $ComputerFileSelector = New-Object System.Windows.Forms.OpenFileDialog
        $ComputerFileSelector.InitialDirectory = [Environment]::GetFolderPath("Desktop")
        $ComputerFileSelector.Filter = "TXT Files (*.txt) | *.txt"
        $null = $ComputerFileSelector.ShowDialog()
        $File = $ComputerFileSelector.FileName
        [array]$ComputersArray = @()
        Get-Content -Path $File | ForEach-Object {$ComputersArray += $_}
        return $ComputersArray
    }
    Log "Getting enabled computer accounts"
    $DirectorySearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
    $DirectorySearcher.Filter = "(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
    $DirectorySearcher.PageSize = 100000
    try {
        $DomainComputers = ($DirectorySearcher.Findall())
    } catch {
        Log "Error retrieving computer accounts"
        Log $_.Exception.Message
    }
    [array]$ComputersArray = @()
    ForEach ($PC in $DomainComputers){
        #Log $PC.Properties.dnshostname
        $ComputersArray += $PC.Properties.dnshostname
    }
    return $ComputersArray
}


function AggregateData {
    Log "Aggregating Data..."
    $mainfile = $main_storage + "\evtx_hunt_output_$milli.csv"
    $files = Get-ChildItem -Filter *.csv -Path $device_storage_root | Select-Object -ExpandProperty FullName
    foreach ($file in $files){
        Log "Merging: $file"
        $file | Import-Csv | Export-Csv $mainfile -NoTypeInformation -Append
    }
    Log "All Data Merged to: $mainfile"
}

function TestCredentials {

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('domain')
    if (-not($DS.ValidateCredentials($credentials.GetNetworkCredential().UserName, $credentials.GetNetworkCredential().Password)))
    {
        Log "Invalid Credentials!"
        exit
    }
}

function WriteLogo {
    $logo = "
*********************************************
*    ___         __  __    __  ___          *
*   /   | __  __/ /_/ /_  /  |/  /___ _____ *
*  / /| |/ / / / __/ __ \/ /|_/ / __ `/ __  \*
* / ___ / /_/ / /_/ / / / /  / / /_/ / /_/ /*
*/_/  |_\__,_/\__/_/ /_/_/  /_/\__,_/ .___/ *
*                                  /_/      *
*********************************************
    "
    Write-Host $logo
    Write-Host "AuthMap - Joe Avanzato"
    Write-Host "https://github.com/joeavanzato/AuthMap"
    Write-Host ""
}

function Main {
    WriteLogo
    TestCredentials
    CreateStorageDirectories
    $computers = GetComputers
    if ($computers.Count -eq 0){
        Log "Exiting - No Computers Found!"
        exit
    }
    $filter = @{
    LogName='Security';
    ProviderName='Microsoft-Windows-Security-Auditing';
    ID=4624;
    StartTime=(Get-Date).AddDays(-1).Date
    }

    $filterxp = ""
    $filterxpuser = "*[System[EventID=4624] and (EventData[Data[@Name='TargetUserName']='$targetusername'] and (EventData[Data[@Name='LogonType']='10'] or EventData[Data[@Name='LogonType']='3']))] and *[System[TimeCreated[timediff(@SystemTime) <= $milliseconds]]]"
    $filterxpnouser = "*[System[EventID=4624] and (EventData[Data[@Name='LogonType']='10'] or EventData[Data[@Name='LogonType']='3'])] and *[System[TimeCreated[timediff(@SystemTime) <= $milliseconds]]]"

    $filterxpuser = "*[System[EventID=4624] and EventData[Data[@Name='TargetUserName']='$targetusername']$logontype_filterstring] and *[System[TimeCreated[timediff(@SystemTime) <= $milliseconds]]]"
    $filterxpnouser = "*[System[EventID=4624]$logontype_filterstring] and *[System[TimeCreated[timediff(@SystemTime) <= $milliseconds]]]"
    if ($targetusername -eq "*"){
        $filterxp = $filterxpnouser
    } else {
        $filterxp = $filterxpuser
    }
    $sb = "
        try {
        `$records = Get-WinEvent -ProviderName 'Microsoft-Windows-Security-Auditing' -FilterXPath `"$filterxp`";
        `$outItems = New-Object System.Collections.Generic.List[System.Object];
        ForEach (`$r in `$records){
            `$eventXml = ([xml]`$r.ToXml()).Event
            `$Object = New-Object PSObject -Property @{
                EventId = `$r.Id
                RecordId = `$r.RecordId
                LogName = `$r.LogName
                ProviderName = `$r.ProviderName
                ProcessId = `$r.ProcessId
                MachineName = `$eventXml.System.Computer
                TimeCreated = `$r.TimeCreated
                SubjectUser = ''
                SubjectDomain = ''
                TargetUser = ''
                TargetDomain = ''
                KeywordsDisplayNames = `$r.KeywordsDisplayNames[0]
                LogonType = ''
                ProcessName = ''
                WorkstationName = ''
                SourceNetworkAddress = ''
                LmPackageName = ''
            };
            `$eventXml.EventData.ChildNodes | ForEach-Object {
                if (`$_.Name -eq 'SubjectUserName'){
                    `$Object.SubjectUser = (`$_).'#text'
                } elseif (`$_.Name -eq 'SubjectDomainName'){
                    `$Object.SubjectDomain = (`$_).'#text'
                } elseif (`$_.Name -eq 'TargetUserName'){
                    `$Object.TargetUser = (`$_).'#text'
                } elseif (`$_.Name -eq 'TargetDomainName'){
                    `$Object.TargetDomain = (`$_).'#text'
                } elseif (`$_.Name -eq 'LogonType'){
                    `$Object.LogonType = (`$_).'#text'
                } elseif (`$_.Name -eq 'ProcessName'){
                    `$Object.ProcessName = (`$_).'#text'
                } elseif (`$_.Name -eq 'WorkstationName'){
                    `$Object.WorkstationName = (`$_).'#text'
                } elseif (`$_.Name -eq 'IpAddress'){
                    `$Object.SourceNetworkAddress = (`$_).'#text'
                } elseif (`$_.Name -eq 'LmPackageName'){
                    `$Object.LmPackageName = (`$_).'#text'
                }
            };
            `$outItems.Add(`$Object);
        }
        `$outItems | Export-CSV -Path '$output_file_path' -NoTypeInformation
    } catch {
        `$outItems | Export-CSV -Path '$output_file_path' -NoTypeInformation
    }
    "
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($sb)
    $command = [Convert]::ToBase64String($bytes)
    $executionstring = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand `"$command`""
    $totalcomputers = $computers.Length
    $hostname =  [System.Net.DNS]::GetHostByName($Null).HostName
    #Write-Host $executionstring



    #exit

    $poolblock = "
    param(`$computer, `$credentials, `$settings);
    if (-not (Test-Connection `$computer -ErrorAction SilentlyContinue)){
        return
    }
    `$settings.reachabledevices.Add(`$computer) | Out-Null
    if (`$computer -icontains '$hostname'){
        Invoke-WmiMethod -ComputerName `$computer -Class Win32_Process -Name Create -ArgumentList '$executionstring'
    } else {
        Invoke-WmiMethod -ComputerName `$computer -Credential `$credentials -Class Win32_Process -Name Create -ArgumentList '$executionstring'
    }
    `$settings.launchedjobs += 1
    "
    $ScriptBlock = [ScriptBlock]::Create($poolblock)
    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $concurrencylimit, $SessionState, $Host)
    $RunspacePool.Open()
    $Jobs = New-Object System.Collections.ArrayList
    $computers | ForEach-Object {
        $PowerShell = [powershell]::Create()
	    $PowerShell.RunspacePool = $RunspacePool
        $computer = $_
        $settings.hostcount += 1
        Log "Starting $computer - $($settings.hostcount)/$totalcomputers"
        $PowerShell.AddScript($ScriptBlock).AddArgument($computer).AddArgument($credentials).AddArgument($settings) | Out-Null
        $Job = New-Object -TypeName PSObject -Property @{
            Runspace = $PowerShell.BeginInvoke()
            Powershell = $PowerShell
        }
        $Jobs.Add($Job) | Out-Null
        return


        #if (-not (Test-Connection $computer -ErrorAction SilentlyContinue)){
        #    Write-Host "Host Not Reachable: $computer"
        #    return
        #}
        #$settings.reachabledevices.Add($computer) | Out-Null
        #if ($computer -icontains $hostname){
        #    $execute = Invoke-WmiMethod -ComputerName $computer -Class Win32_Process -Name Create -ArgumentList "$executionstring"
        #} else {
        #    $execute = Invoke-WmiMethod -ComputerName $computer -Credential $credentials -Class Win32_Process -Name Create -ArgumentList "$executionstring"
        #}
        #return
        # Old Method
<#        $scriptblock
        $settings.hostcount += 1
        $currentcount = $settings.hostcount
        Log "Starting $computer : [$currentcount/$totalcomputers]"
        Start-ThreadJob -ThrottleLimit $concurrencylimit {
            #$computer = $using:computer
            #$settings = $using:settings
            #Write-Host "Host Count: "$settings.hostcount
            if (-not (Test-Connection $computer -ErrorAction SilentlyContinue)){
                #Write-Host "Host Not Reachable: $computer"
                return
            }
            $settings.reachabledevices.Add($computer) | Out-Null
            if ($computer -icontains $hostname){
                $execute = Invoke-WmiMethod -ComputerName $computer -Class Win32_Process -Name Create -ArgumentList "$executionstring"
            } else {
                $execute = Invoke-WmiMethod -ComputerName $computer -Credential $using:credentials -Class Win32_Process -Name Create -ArgumentList "$executionstring"
            }
        }#>
    } #| Receive-Job -Wait -AutoRemoveJob

    while ($Jobs.Runspace.IsCompleted -contains $false) {
        Log "Waiting for WMI Jobs to finish launching...[$($settings.launchedjobs) / $($settings.reachabledevices.Count)]"
        Start-Sleep -Milliseconds 1000
    }
    $totalreachable = $settings.reachabledevices.Count
    Log "Started all remote tasks - waiting for outputs - Total Started: $totalreachable"
    $done = 0
    $copyJobs = New-Object System.Collections.ArrayList
    while ($true){
        Start-Sleep -Milliseconds 5000
        if ($settings.reachabledevices.Count -eq 0){
            Log "Done Reading Remote Files - waiting for all copy jobs to finish..."
            break
        }
        Log "Checking for new results - Current Progress: [$done / $totalreachable]"
        foreach ($i in $settings.reachabledevices.Clone()){
            # Check and see if output file exists yet - if it does, copy to local device folder with appropriate name
            $source_file = "\\$i\C`$\$($split[1].Trim())"
            if (Test-Path $source_file) {
                $dest_file = $device_storage_root +"\"+ $i + ".csv"
                $done += 1
                #Start-ThreadJob -ScriptBlock { Copy-Item $target_file $targetfile } -ThrottleLimit 32
                $job = Start-ThreadJob -ScriptBlock {param($source_file,$dest_file) Copy-item $source_file $dest_file; Remove-Item $source_file} -ArgumentList $source_file,$dest_file -ThrottleLimit $concurrencylimit | Out-Null
                $copyJobs.Add($job) | Out-Null
                #Copy-Item $source_file $dest_file
                $settings.reachabledevices.Remove($i)
                Log "Getting Results: $source_file [$done/$totalreachable]"
            }
        }
    }
    Get-Job | Receive-Job -Wait -AutoRemoveJob
    AggregateData

}


Main
