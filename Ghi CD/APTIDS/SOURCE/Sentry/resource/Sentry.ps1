# $ErrorActionPreference = "SilentlyContinue"
# $ProgressPreference = "SilentlyContinue"
# Add-Type -assembly System.Security
function Sentry{
	Param (
		[switch]$Analysis
	)
	Begin {
        Write-Host "[+]Start Sentry." -foregroundcolor "green"
		Write-Host "[+]Import Modules." -foregroundcolor "green"
		Write-Host "==> Import Invoke-ScheduledTask." -foregroundcolor "yellow"
		Import-Module ".\Invoke-ScheduledTask.psm1"
		Write-Host "==> Import Invoke-Service." -foregroundcolor "yellow"
		Import-Module ".\Invoke-Service.psm1"
		Write-Host "==> Import Invoke-File." -foregroundcolor "yellow"
		Import-Module ".\Invoke-File.psm1"
		Write-Host "==> Import Invoke-Registry." -foregroundcolor "yellow"
		Import-Module ".\Invoke-Registry.psm1"
		Write-Host "==> Import Invoke-Virustotal." -foregroundcolor "yellow"
		Import-Module ".\Invoke-Virustotal.psm1"
		Write-Host "==> Import Invoke-EventLog." -foregroundcolor "yellow"
		Import-Module ".\Invoke-EventLog.psm1"
		Write-Host "==> Import Invoke-Brute." -foregroundcolor "yellow"
		Import-Module ".\Invoke-Brute.psm1"
		Write-Host "==> Import Invoke-Process." -foregroundcolor "yellow"
		Import-Module ".\Invoke-Process.psm1"
		Write-Host "==> Import Invoke-Port." -foregroundcolor "yellow"
		Import-Module ".\Invoke-Port.psm1"
		Write-Host "==> Import Invoke-NetworkAnalysis." -foregroundcolor "yellow"
		Import-Module ".\Invoke-NetworkAnalysis.psm1"
		Write-Host "==> Import Invoke-NetworkRecon." -foregroundcolor "yellow"
		Write-Host "==> Import Invoke-Trap." -foregroundcolor "yellow"
	}
	Process {
		if($Analysis){
			Write-Host "[+]Run Modules." -foregroundcolor "green"
			Write-Host "==> Run Invoke-ScheduledTask." -foregroundcolor "yellow"
			Invoke-ScheduledTask -Analysis
		}
		else{
			Write-Host "[+]Run Modules." -foregroundcolor "green"
			Write-Host "==> Run Invoke-ScheduledTask." -foregroundcolor "yellow"
			# Invoke-ScheduledTask
			Write-Host "==> Run Invoke-Service." -foregroundcolor "yellow"
			#Invoke-Service
			Write-Host "==> Run Invoke-File." -foregroundcolor "yellow"
			# Invoke-File
			Write-Host "==> Run Invoke-Registry." -foregroundcolor "yellow"
			# Invoke-Registry
			Write-Host "==> Run Invoke-Virustotal." -foregroundcolor "yellow"
			$test = Invoke-Virustotal "C:\cygwin64\Cygwin.bat"
			# Write-Host ($test.VTReport)
			Write-Host "==> Run Invoke-EventLog." -foregroundcolor "yellow"
			# Invoke-EventLog
			Write-Host "==> Run Invoke-Brute." -foregroundcolor "yellow"
			# Invoke-Brute -days 1
			Write-Host "==> Run Invoke-Process." -foregroundcolor "yellow"
			# Invoke-Process
			Write-Host "==> Run Invoke-Port." -foregroundcolor "yellow"
			# Invoke-Port
			Write-Host "==> Run Invoke-NetworkAnalysis." -foregroundcolor "yellow"
			 Invoke-NetworkAnalysis -Hosts 192.168.2.14 -TimeOut 30
			 Write-Host "==> Run Invoke-NetworkRecon." -foregroundcolor "yellow"
			 Write-Host "==> Run Invoke-Trap." -foregroundcolor "yellow"
		}
		
	}
	End {
		Write-Host "[+]Remove Modules." -foregroundcolor "green"
		Write-Host "==> Remove Invoke-ScheduledTask." -foregroundcolor "yellow"
		Remove-Module Invoke-ScheduledTask
		Write-Host "==> Remove Invoke-Service." -foregroundcolor "yellow"
		Remove-Module Invoke-Service
		Write-Host "==> Remove Invoke-File." -foregroundcolor "yellow"
		Remove-Module Invoke-File
		Write-Host "==> Remove Invoke-Registry." -foregroundcolor "yellow"
		Remove-Module Invoke-Registry
		Write-Host "==> Remove Invoke-Virustotal." -foregroundcolor "yellow"
		Remove-Module Invoke-Virustotal
		Write-Host "==> Remove Invoke-EventLog." -foregroundcolor "yellow"
		Remove-Module Invoke-EventLog
		Write-Host "==> Remove Invoke-Brute." -foregroundcolor "yellow"
		Remove-Module Invoke-Brute
		Write-Host "==> Remove Invoke-Process." -foregroundcolor "yellow"
		Remove-Module Invoke-Process
		Write-Host "==> Remove Invoke-Port." -foregroundcolor "yellow"
		Remove-Module Invoke-Port
		Write-Host "==> Remove Invoke-NetworkAnalysis" -foregroundcolor "yellow"
		Remove-Module Invoke-NetworkAnalysis
		Write-Host "==> Remove Invoke-NetworkRecon" -foregroundcolor "yellow"
		Write-Host "==> Remove Invoke-Trap" -foregroundcolor "yellow"
        Write-Host "Done."
    }
}

Sentry