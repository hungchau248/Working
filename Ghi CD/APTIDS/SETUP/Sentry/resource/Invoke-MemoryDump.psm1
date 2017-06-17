function Invoke-MemoryDump {
	<#   

	.SYNOPSIS   
		Get Windows memory crash dump configuration or analyze the memory crash dump configuration
	  
	.DESCRIPTION   
		Allows the administrator to get windows memory crash dump configuration from the system locally or remotely.
		
		By default without any parameters, the cmdlet will only get the Windows memory crash dump configuration.
		
		Remote Requirements
		1. Remote Registry Service must to be enabled on the remote machine.
		2. Remote Registry Service must be in a running state on the remote machine.
		3. Administrator must have sufficient permission to access the registry remotely.

	.PARAMETER ComputerName
		
		Specify a hostname

	.PARAMETER Analyze

		ALIAS -A
		
		Specify the cmdlet to analyze the memory crash dump configuration.
		
	.EXAMPLE

		Invoke-MemoryDump
		
		HostName         : REDMOND
		OperatingSystem  : Microsoft Windows 8 Pro
		DumpFilters      : {dumpfve.sys}
		LogEvent         : 1
		Overwrite        : 1
		AutoReboot       : 1
		DumpFile         : C:\Windows\MEMORY.DMP
		MinidumpsCount   : 50
		MinidumpDir      : C:\Windows\Minidump
		CrashDumpEnabled : 7 - Automatic Memory Dump
		LastCrashTime    : 10/16/2012 19:58:24
		
		This command simply get the Windows Memory Dump configuration
			
	.LINK

		Overview of memory dump file options for Windows 2000, Windows XP, Windows Server 2003, Windows Vista, 
		Windows Server 2008, Windows 7, and Windows Server 2008 R2

		http://support.microsoft.com/kb/254649

		Windows feature lets you generate a memory dump file by using the keyboard
		
		http://support.microsoft.com/kb/244139

		Win32_PhysicalMemory Class

		http://msdn.microsoft.com/en-us/library/windows/desktop/aa394347(v=vs.85).aspx

		Win32_PageFileSetting Class

		http://msdn.microsoft.com/en-us/library/windows/desktop/aa394245(v=vs.85).aspx

		Win32_LogicalDisk Class

		http://msdn.microsoft.com/en-us/library/windows/desktop/aa394173(v=vs.85).aspx

	.NOTES   
		Author  : Ryen Kia Zhi Tang
		Date    : 25/12/2012
		Blog    : ryentang.blogspot.com
		Version : 1.0

	#>

	[CmdletBinding(
		SupportsShouldProcess=$True,
		ConfirmImpact='High')]

	param (

	[Parameter(
		Mandatory=$False,
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$True)]
		
		$ComputerName = $env:computername,
		
	[Parameter(
		Mandatory=$False,
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$True)]
		[Alias('A')]
		[Switch] $Analyze

	)

	BEGIN {
		
		#clear variable
		$DriveLetter = ""
		$MiniDumpDirLength = 0
	}

	PROCESS {

		#create an object to store data
		$Object = New-Object PSObject

		#extract registry value
		try {
			$RemoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
			$RemoteRegistryKey= $RemoteRegistry.OpenSubKey("System\\CurrentControlSet\\Control\\CrashControl" )
	  
		}catch{
			Write-Error "Remote Registry Error >> $_"
		}



		#wmi query for logical disks, physical memory, page file settings and operating system
		try {

			$Win32_LogicalDisk = Get-WmiObject -ComputerName $ComputerName -Class Win32_LogicalDisk -ErrorVariable Win32_LogicalDisk_Error
			$Win32_PhysicalMemory = Get-WmiObject -ComputerName $ComputerName -Class Win32_PhysicalMemory -ErrorVariable Win32_PhysicalMemory_Error
			$Win32_PageFileSetting = Get-WmiObject -ComputerName $ComputerName -Class Win32_PageFileSetting -ErrorVariable Win32_PageFileSetting_Error
			$Win32_OperatingSystem = Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem -ErrorVariable Win32_OperatingSystem_Error | Select-Object Caption, OSArchitecture
			$Win32_PerfRawData_PerfOS_Memory = Get-WmiObject -ComputerName $ComputerName -Class Win32_PerfRawData_PerfOS_Memory -ErrorVariable Win32_PerfRawData_PerfOS_Memory_Error | Select-Object PoolPagedBytes, PoolNonpagedBytes
		
		}catch{
			Write-Error $ComputerName ">>" $_.ToString()
		}
		
		####
		$Object | Add-Member -MemberType noteproperty -Name "HostName" -value $ComputerName
		$Object | Add-Member -MemberType noteproperty -Name "OperatingSystem" -value $Win32_OperatingSystem.Caption

		foreach($KeyName in $RemoteRegistryKey.GetValueNames()) {
			$Object | Add-Member -MemberType noteproperty -Name $KeyName -value $RemoteRegistryKey.GetValue($KeyName)
		}

		#verify if there is an existing dump file
		try {
		
			#verify CrashDumpEnabled is not small memory dump
			if($Object.CrashDumpEnabled -ne 3) {
			
				$DumpFile = Get-ChildItem $Object.DumpFile -ErrorAction Stop -ErrorVariable -ErrorVariable DumpFile_Error
			
				$Object | Add-Member -MemberType noteproperty -Name "DumpFileExists" -value $True
			
			}else{
			
				$DumpFile = Get-ChildItem $Object.MinidumpDir -Filter *.DMP -ErrorAction Stop -ErrorVariable MinidumpDir_Error
				
				#enumerate total mini dump files length
				foreach($MiniDumpFile in $DumpFile) { $MiniDumpDirLength += $MiniDumpFile.Length }
				
				$Object | Add-Member -MemberType noteproperty -Name "MinidumpDirExists" -value $True
			
			} #end of #verify CrashDumpEnabled is not small memory dump
			
		}catch{
			
			if($DumpFile_Error) {
				$DumpFile = 0
				$Object | Add-Member -MemberType noteproperty -Name "DumpFileExists" -value $False
			}
			
			elseif($MinidumpDir_Error) {
				$MiniDumpDirLength = 0
				$Object | Add-Member -MemberType noteproperty -Name "MinidumpDirExists" -value $False
			}
		
		} #end of #verify if there is an existing dump file
		
		switch($Object.CrashDumpEnabled) {
			0 { $DriveLetter = ""; $Object | Add-Member -MemberType NoteProperty -Name "CrashDumpEnabled" -Value "0 - None" -Force } #none
			1 { $DriveLetter = $Object.DumpFile.Substring(0,2); $Object | Add-Member -MemberType NoteProperty -Name "CrashDumpEnabled" -Value "1 - Complete Memory Dump" -Force} #complete memory dump
			2 { $DriveLetter = $Object.DumpFile.Substring(0,2); $Object | Add-Member -MemberType NoteProperty -Name "CrashDumpEnabled" -Value "2 - Kernel Memory Dump" -Force } #kernel memory dump
			3 { $DriveLetter = $Object.MinidumpDir.Substring(0,2); $Object | Add-Member -MemberType NoteProperty -Name "CrashDumpEnabled" -Value "3 - Small Memory Dump" -Force } #small memory dump
			7 { $DriveLetter = $Object.MinidumpDir.Substring(0,2); $Object | Add-Member -MemberType NoteProperty -Name "CrashDumpEnabled" -Value "7 - Automatic Memory Dump" -Force } #automatic memory dump
		}
		if($Object.LastCrashTime -ne $null) {
			$Value = [DateTime]::FromFileTime([int64]::Parse($Object.LastCrashTime)); $Object | Add-Member -MemberType NoteProperty -Name "LastCrashTime" -Value "$Value" -Force
		}


	#### Physical Memory
		if($Analyze) {

			foreach($itemWin32_PhysicalMemory in $Win32_PhysicalMemory) {
				$PhysicalMemory = $PhysicalMemory + $itemWin32_PhysicalMemory.Capacity
			}

			$Object | Add-Member -MemberType noteproperty -Name "PhysicalMemory" -value $PhysicalMemory
			$Object | Add-Member -MemberType noteproperty -Name "KernelMemory" -value $($Win32_PerfRawData_PerfOS_Memory.PoolPagedBytes + $Win32_PerfRawData_PerfOS_Memory.PoolNonpagedBytes)
		}

	#### Page File
		if($Analyze) {

			foreach($itemWin32_PageFileSetting in $Win32_PageFileSetting) {
				$Object | Add-Member -MemberType noteproperty -Name "PageFile" -value $itemWin32_PageFileSetting.Name
				$Object | Add-Member -MemberType noteproperty -Name "PageFileInitialSize" -value $($itemWin32_PageFileSetting.InitialSize*1MB)
				$Object | Add-Member -MemberType noteproperty -Name "PageFileMaximumSize" -value $($itemWin32_PageFileSetting.MaximumSize*1MB)
			}

			if($Object.PageFile -ne $null) {
				#set "Automatically manage paging file size for all drives" as False
				$Object | Add-Member -MemberType noteproperty -Name "AutomaticManagePageFileSize" -value "False"
			}else{
				#set "Automatically manage paging file size for all drives" as True
				$Object | Add-Member -MemberType noteproperty -Name "AutomaticManagePageFileSize" -value "True"
			}
		}
			
	#### Logical Disk
		if($Analyze) {

			foreach($itemWin32_LogicalDisk in $Win32_LogicalDisk) {
			
				#verify DriveLetter matches itemWin32_LogicalDisk.DeviceID
				if($DriveLetter -eq $itemWin32_LogicalDisk.DeviceID) {            
					
					$Object | Add-Member -MemberType noteproperty -Name "LogicalDiskDriveLetter" -value $itemWin32_LogicalDisk.Name
					$Object | Add-Member -MemberType noteproperty -Name "LogicalDiskSize" -value $itemWin32_LogicalDisk.Size
					$Object | Add-Member -MemberType noteproperty -Name "LogicalDiskFreeSpace" -value $itemWin32_LogicalDisk.FreeSpace

				} #end of #verify DriveLetter matches itemWin32_LogicalDisk.DeviceID
		
			} #end of #foreach($itemWin32_LogicalDisk in $Win32_LogicalDisk)

		}

	#### Verify DedicatedDumpFileIsConfigured Registry Key
		if($Analyze) {

			if($Object.PageFile -ne $null) { 

				#verify DumpFile is configured to C: drive for the correct operating system version
				if($Object.LogicalDiskDriveLetter -ne $Object.PageFile.Substring(0,2)) {
			
					#verify operating is Windows Server 2008 or Windows Vista
					if(($Win32_OperatingSystem.Caption -like "Microsoft Windows Server 2008 ") -or ($Win32_OperatingSystem.Caption -like "Microsoft Vista*")) {
				
						#verify DedicatedDumpFile is configured because DumpFile location is not on C: drive
						if($Object.DedicatedDumpFile) {
					
							#In Windows Vista and in Windows Server 2008, to put a paging file on another partition, you must create a new registry entry that is named DedicatedDumpFile.
							$Object | Add-Member -MemberType noteproperty -Name "DedicatedDumpFileIsConfigured" -value $True
				
						}else{
					
							#If DedicatedDumpFile is not configured, there will be no crash dump.
							$Object | Add-Member -MemberType noteproperty -Name "DedicatedDumpFileIsConfigured" -value $False
				
						} #end of #verify DedicatedDumpFile is configured because DumpFile location is not on C: drive
			
					} #end of #verify operating is Windows Server 2008 or Windows Vista
			
					#verify operating is Windows Server 2008 R2 or Windows 7
					elseif(($Win32_OperatingSystem.Caption -like "Microsoft Windows 7*") -or ($Win32_OperatingSystem.Caption -like "Microsoft Windows Server 2008*")) {
				
						#In Windows 7 and in Windows Server 2008 R2, you do not have to use the DedicatedDumpFile registry entry to put a paging file onto another partition.
						$Object | Add-Member -MemberType noteproperty -Name "DedicatedDumpFileIsConfigured" -value "NotRequired"
			
					}else{
				
						#If operating system is not Windows Vista, Windows 7, Windows Server 2008, Windows Server 2008 R2, DedicatedDumpFile registry entry is not available. PageFile and DumpFile must be in boot volume.
						$Object | Add-Member -MemberType noteproperty -Name "DedicatedDumpFileIsConfigured" -value "NotAvailable"
			
					} #end of #verify operating is Windows Server 2008 R2 or Windows 7
			
				}else{
			
					#set dedicateddumpfile is not required if dumpfile is configured to C: drive
					$Object | Add-Member -MemberType noteproperty -Name "DedicatedDumpFileIsConfigured" -value "NotRequired"
		
				} #end of #verify DumpFile is configured to C: drive for the correct operating system version
		
			}

			#verify CrashDumpEnabled configuration for analysis
			switch($Object.CrashDumpEnabled) {
		
				0 { $Object | Add-Member -MemberType noteproperty -Name "CrashDumpStatus" -value "Disabled" } #none
			
			
			
			
			
				1 { #complete memory dump
			
					#verify page file maximum size is greater than physical memory plus 1MB
					if($Object.PageFileMaximumSize -gt $($Object.PhysicalMemory + 1MB)) {
				
						$Object | Add-Member -MemberType noteproperty -Name "SufficientPageFile" -value $True
				
					}else{
				
						$Object | Add-Member -MemberType noteproperty -Name "SufficientPageFile" -value $False

					} #end of #verify page file maximum size is greater than physical memory plus 1MB
				
				
				
					#verify logical disk free space is greater than physical memory plus 1MB
					if($Object.LogicalDiskFreeSpace -gt $($Object.PhysicalMemory + 1MB)) {
					
						$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $True
					
					}else{
					
						#verify dump file exist and overwrite is enabled
						switch($Object.DumpFileExists) {
						
							$True {
							
								#verify existing dump file can be overwritten
								if($Object.Overwrite -eq 1) {
							
									#verify current free space plus existing dump file size is greater than physical memory plus 1MB
									if(($Object.LogicalDiskFreeSpace + $DumpFile.Length) -gt $($Object.PhysicalMemory + 1MB)) {
								
										$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $True
								
									}else{
								
										$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
								
									}
								
								}else{
							
									$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
							
								} #end of #verify existing dump file can be overwritten and current free space plus existing dump file size is greater than physical memory plus 1MB
						
							} #end of #DumpFileExists is $True
						
						
							$False {
						
								$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
						
							} #end of #DumpFileExists is $False
						
						} #end of #verify dump file exist and overwrite is enabled

					} #end of #verify logical disk free space is greater than physical memory plus 1MB
				
				
				
					#verify operating system is 32bit and physical memory is not greater than 2GB for complete memory dump
					if(($Win32_OperatingSystem.OSArchitecture -eq "32-Bit") -and ($Object.PhysicalMemory -gt 2GB)){
				
						#The Complete memory dump option is not available on computers that are running a 32-bit operating system and that have 2 gigabytes (GB) or more of RAM.
						$Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "NotPossible"
				
					} #end of #verify operating system is 32bit and physical memory is not greater than 2GB
				
				
					#verify Object.SufficientFreeSpace and Object.SufficientPageFile is true
					elseif(($Object.SufficientFreeSpace -eq $True) -and ($Object.SufficientPageFile -eq $True)) {
					
						#verify Object.DedicatedDumpFileIsConfigured is not False or NotAvailable
						if(($Object.DedicatedDumpFileIsConfigured -ne $False) -or ($Object.DedicatedDumpFileIsConfigured -ne "NotAvailable")) {
						
							$Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "Possible"
					
						}else{
					
							$Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "NotPossible"

						} #end of #verify Object.DedicatedDumpFileIsConfigured is not False or NotAvailable
					
					}else{
					
						$Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "NotPossible"
				
					} #end of #verify Object.SufficientFreeSpace and Object.SufficientPageFile is true
						
				} #end of #complete memory dump
			
			
			
			
			
				2 { #kernel memory dump
				
					#verify page file maximum size is greater than physical memory plus 1MB
					if($Object.PageFileMaximumSize -gt (2GB + 1MB)) {
				
						$Object | Add-Member -MemberType noteproperty -Name "SufficientPageFile" -value $True
				
					}else{
				
						$Object | Add-Member -MemberType noteproperty -Name "SufficientPageFile" -value $False

					} #end of #verify page file maximum size is greater than physical memory plus 1MB
				
				
					#verify logical disk free space is greater than 2GB
					if($Object.LogicalDiskFreeSpace -gt (2GB + 1MB)) {
					
						$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $True
					
					}else{
				
						#verify dump file exist
						switch($Object.DumpFileExists) {
					
							$True {
							
								#verify existing dump file can be overwritten
								if($Object.Overwrite -eq 1) {
							
									#verify current free space plus existing dump file size is greater than 2GB
									if(($Object.LogicalDiskFreeSpace + $DumpFile.Length) -gt (2GB + 1MB)) {
								
										$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $True
								
									}else{
								
										$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
								
									} #end of #verify current free space plus existing dump file size is greater than 2GB
								
								}else{
							
									#verify current free space is greater than current kernel memory
									if($Object.LogicalDiskFreeSpace -gt $($Object.KernelMemory + 1MB)) {
									
										$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value "Plausible"
								
									}else{
								
										$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
								
									} #end of #verify current free space is greater than current kernel memory
							
								} #end of #verify existing dump file can be overwritten
							
							} #end of #DumpFileExists is $True
						
							$False {
						
								$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
						
							} #end of #DumpFileExists is $False
					
						} #end of #verify dump file exist
				   
					} #end of #verify logical disk free space is greater than 2GB
				


					#verify Object.SufficientFreeSpace is true
					if(($Object.SufficientFreeSpace -eq $True) -and ($Object.SufficientPageFile -eq $True)) {
					
						#verify Object.DedicatedDumpFileIsConfigured is not False or NotAvailable
						if(($Object.DedicatedDumpFileIsConfigured -ne $False) -or ($Object.DedicatedDumpFileIsConfigured -ne "NotAvailable")) {
						
							$Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "Possible"
					
						}else{
					
							$Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "NotPossible"

						} #end of #verify Object.DedicatedDumpFileIsConfigured is not False or NotAvailable
				
					}else{
					
						$Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "NotPossible"
				
					} #end of #verify Object.SufficientFreeSpace and Object.SufficientPageFile is true
				
				} #end of #kernel memory dump
			
			
			
			
			
				3 { 
				 
					#verify logical disk free space is greater than total MinidumpsCount
					if(($Win32_OperatingSystem.OSArchitecture -eq "32-Bit") -and ($Object.LogicalDiskFreeSpace -gt ($Object.MinidumpsCount * 64KB))) {
					
						#A small memory (aka Mini-dump) is a 64KB dump on 32-bit System
						$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $True
					
					}
				
					elseif(($Win32_OperatingSystem.OSArchitecture -eq "64-Bit") -and ($Object.LogicalDiskFreeSpace -gt ($Object.MinidumpsCount * 128KB))){

						#A small memory (aka Mini-dump) is a 128KB dump on 64-bit System
						$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $True            
					}
				
					else{
				
						#verify dump file exist
						switch($Object.DumpFileExists) {
					
							$True { 
						
							} #end of #DumpFileExists is $True
											
							$False {
						
								$Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
							
							} #end of #DumpFileExists is $False
						
						} #end of #verify dump file exist
					
					} #end of #verify logical disk free space is greater than total MinidumpsCount
			
				} #small memory dump
		
			} #end of #verify CrashDumpEnabled configuration for analysis

		} #end of Analyze parameter

	$Object | Sort-Object -Property Name -Descending;
	if($Object.AutomaticManagePageFileSize -eq "True") { Write-Host "*** Unable to further analyze due to System Managed Pagefile size ***" }
	}

	END { }

} #end of #function Get-MemoryDump