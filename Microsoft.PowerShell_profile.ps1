
# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If so and the current host is a command line, then change to red color 
# as warning to user that they are operating in an elevated context
if (($host.Name -match "ConsoleHost") -and ($isAdmin))
{
     $host.UI.RawUI.BackgroundColor = "DarkRed"
     $host.PrivateData.ErrorBackgroundColor = "White"
     $host.PrivateData.ErrorForegroundColor = "DarkRed"
     Clear-Host
}

# Useful shortcuts for traversing directories
function cd...  { cd ..\.. }
function cd.... { cd ..\..\.. }

# Compute file hashes - useful for checking successful downloads 
function md5    { Get-FileHash -Algorithm MD5 $args }
function sha1   { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }

# Quick shortcut to start notepad
function n      { notepad $args }

# Drive shortcuts
function HKLM:  { Set-Location HKLM: }
function HKCU:  { Set-Location HKCU: }
function Env:   { Set-Location Env: }

# Creates drive shortcut for Work Folders, if current user account is using it
if (Test-Path "$env:USERPROFILE\Work Folders")
{
    New-PSDrive -Name Work -PSProvider FileSystem -Root "$env:USERPROFILE\Work Folders" -Description "Work Folders"
    function Work: { Set-Location Work: }
}

# Creates drive shortcut for OneDrive, if current user account is using it
if (Test-Path HKCU:\SOFTWARE\Microsoft\OneDrive)
{
    $onedrive = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\OneDrive
    if (Test-Path $onedrive.UserFolder)
    {
        New-PSDrive -Name OneDrive -PSProvider FileSystem -Root $onedrive.UserFolder -Description "OneDrive"
        function OneDrive: { Set-Location OneDrive: }
    }
    Remove-Variable onedrive
}

function Show-CSV {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )
    $data = Import-Csv -Path $Path
    #write-host($data) 
    $data | Out-GridView
}



# Set up command prompt and window title. Use UNIX-style convention for identifying 
# whether user is elevated (root) or not. Window title shows current version of PowerShell
# and appends [ADMIN] if appropriate for easy taskbar identification
function prompt 
{ 
    if ($isAdmin) 
    {
        "[" + (Get-Location) + "] # " 
    }
    else 
    {
        "[" + (Get-Location) + "] $ "
    }
}

$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
if ($isAdmin)
{
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}

# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs
{
    if ($args.Count -gt 0)
    {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    }
    else
    {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}

# Simple function to start a new elevated process. If arguments are supplied then 
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
function admin
{
    if ($args.Count -gt 0)
    {   
       $argList = "& '" + $args + "'"
       Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $argList
    }
    else
    {
       Start-Process "$psHome\powershell.exe" -Verb runAs
    }
}

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights. 
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin


# Make it easy to edit this profile once it's installed
function Edit-Profile
{
    if ($host.Name -match "ise")
    {
        $psISE.CurrentPowerShellTab.Files.Add($profile.CurrentUserAllHosts)
    }
    else
    {
        Ise $profile
    }
}

# We don't need these any more; they were just temporary variables to get to $isAdmin. 
# Delete them to prevent cluttering up the user profile. 
Remove-Variable identity
Remove-Variable principal

New-Alias ll Get-ChildItem
New-Alias .. Set-Location ..
 

$hushpath = Join-Path -Path $home -ChildPath ".hushlogin"

$trackPath = Join-Path -path $env:TEMP -ChildPath pswelcome.tmp
<#
avkommentera om du vill köra en fil

#on filen är yngre än 24h skapas ingen ny

$AlreadyRun = $False
if (Test-Path -path $trackPath) {
    $f = Get-Item -path $trackPath
    $ts = New-TimeSpan -Start $f.CreationTime -End (Get-Date)
    if ($ts.TotalHours -le 24) {
        $AlreadyRun = $True
    }
}
#>

if ((Test-Path -Path $hushpath) -OR $AlreadyRun) {
    #Hoppa över Welcome
}
else {
    if ($PSEdition -eq 'Desktop') {
        $psname = "Windows PowerShell"
        $psosbuild = $PSVersionTable.BuildVersion
    }
    else {
        $psname = "PowerShell"
        $psosbuild = $PSVersionTable.os
    }

    #Ons Jun 01 13:13:45 EDT 2022
    $welcomeDate = Get-Date -Format "ddd MMM dd hh:mm:ss"

    #hämta tidzon
    $tz = Get-Timezone #[System.TimeZone]::CurrentTimeZone
    if ($tz.IsDaylightSavingTime((Get-Date))) {
        $tzNameString = $tz.DaylightName
    }
    else {
        $tzNameString = $tz.StandardName
    }

    $tzName = ($tznamestring.split() | ForEach-Object {$_[0]}) -join ""

    #Hämta C Usage
    $c = Get-Volume -DriveLetter C
    $used = $c.size - $c.SizeRemaining
    $cusage = "{0:p2} of {1:n0}GB" -f ($used / $c.size), ($c.size / 1GB)

    #Get nic och IP
    #filtrera ut Hyper-V adapters och Loopback
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.addressState -eq 'preferred' -AND $_.InterfaceAlias -notmatch "vEthernet|Loopback" } -outvariable if).IPAddress

    #hämta minnes info
    $os = Get-CimInstance -ClassName win32_operatingsystem -Property TotalVisibleMemorySize, FreePhysicalMemory
    $memUsed = $os.TotalVisibleMemorySize - $os.FreePhysicalMemory
    $memUsage = "{0:p}" -f ($memUsed / $os.TotalVisibleMemorySize)

    #get system performance counters
    $sysPerf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_System -Property Processes, ProcessorQueueLength

    #get pagefile information
    $pagefile = Get-CimInstance -ClassName Win32_PageFileUsage -Property CurrentUsage,AllocatedBaseSize
    $swap = "{0:p}" -f ($pagefile.CurrentUsage/$pagefile.AllocatedBaseSize)
        
    $longest = "IPV4 address for $($if.InterfaceAlias)".length
    function _display {
        param([object]$value,[int]$headlength,[int]$max =$longest)
        $len = ($max - $headlength)+2
        "{0}{1}" -f (' '*$len),$value
    }

    #bygger displayvariabeln
    $out = @"
    
Welcome to $psname $($PSVersionTable.PSVersion) [$psosbuild]   
  
System Information as of $welcomeDate $tzName $((Get-Date).year)

    System load:$(_display -value $sysPerf.ProcessorQueueLength -headlength 11)
    Processes:$(_display -value $sysPerf.Processes -headlength 9 )
    Users logged in:$(_display -value $(((quser).count-1)) -headlength 15)
    Usage of C:$(_display -value $cusage -headlength 10)
    Memory Usage:$(_display -value $memUsage -headlength 12 )
    IPV4 address for $($if.InterfaceAlias):$(_display -value $IP -headlength $longest)
    Swap usage:$(_display -value $swap -headlength 10)

    This message is shown once a day. To disable it please create the
$hushpath file.

"@

    Clear-Host
    #Visa välkommsttext och skicka till tempfil.
    
    $out | Tee-Object -FilePath $trackPath
Get-WmiObject win32_operatingsystem |select @{Name="Last Boot Time"; Expression={$_.ConvertToDateTime($_.LastBootUpTime)}}, PSComputerName
}
function prompt {
    Write-Host "$(Get-Date -Format 'HH:mm:ss') " -NoNewline -ForegroundColor Green
    return "PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) "
}

function Get-LoggedInComputers {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    # Get the domain name
    $Domain = "vgregion.se"
    # Get the user's distinguished name (DN)
    $UserDN = Get-ADUser -Filter {SamAccountName -eq $Username} | Select-Object -ExpandProperty DistinguishedName
    # Get the user's current sessions on domain computers
    $Sessions = Get-WmiObject -Class Win32_ComputerSystem -ComputerName (Get-ADComputer -Filter * | Select-Object -ExpandProperty Name) |
        Where-Object {($_.UserName -ne $null) -and ($_.UserName.EndsWith($UserDN))} |
        Select-Object Name
    # Return the names of the computers that the user is currently logged on to
    $Sessions | Select-Object -ExpandProperty Name
}



Write-Host "`nSystem Info:`n"
Get-WmiObject Win32_OperatingSystem | Format-List Caption, OSArchitecture, Version

$Host.UI.RawUI.ForegroundColor = "Green"
$Host.UI.RawUI.BackgroundColor = "Black"

Write-Host "System information:"
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "  OS: $($os.Caption) $($os.Version)"
$cpu = Get-CimInstance Win32_Processor
Write-Host "  CPU: $($cpu.Name)"
$mem = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
$memSize = [Math]::Round($mem.Sum / 1MB)
Write-Host "  Memory: $memSize GB"

# Set custom color scheme
$consoleColor = @{
    'BackgroundColor' = 'Black'
    'ForegroundColor' = 'Green'
    'ErrorForegroundColor' = 'Red'
    'WarningForegroundColor' = 'Yellow'
    'DebugForegroundColor' = 'Gray'
    'VerboseForegroundColor' = 'White'
}
$host.PrivateData.Colors = $consoleColor