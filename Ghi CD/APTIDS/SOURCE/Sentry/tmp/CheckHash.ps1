param(
	[String]$Task_XML = "HashFile.xml",
	[String]$File_Hash_New = "HashFile_New.log",
	[String]$File_Hash_Check = "HashFile_Check.log",
	[String]$mode = "none",
	[String]$StartBoundary = "2005-10-11T08:00:00",
	[String]$Interval = "PT1M",
	[String]$Duration = "PT4M",
	[String]$DaysInterval = "2",
	[String]$AtLogon = "true",
	[String]$SRC_DIR = "$env:USERPROFILE" + '\Desktop' ###<SRC_DIR>###
)

clear
function Get-FileMD5 {
    Param([string]$file)
    $md5 = [System.Security.Cryptography.HashAlgorithm]::Create("MD5")
    $IO = New-Object System.IO.FileStream($file, [System.IO.FileMode]::Open)
    $StringBuilder = New-Object System.Text.StringBuilder
    $md5.ComputeHash($IO) | % { [void] $StringBuilder.Append($_.ToString("x2")) }
    $hash = $StringBuilder.ToString() 
    $IO.Dispose()
    return $hash
}

Function Update-Hash
{
	Write-Host "" | Out-File $File_Hash_New
	$SRC_DIR = $SRC_DIR.replace('\','\\')
	$SourceFiles = get-childitem -Recurse $SRC_DIR | ? { $_.PSIsContainer -eq $false} #get the files in the source dir.
	$SRC_DIR = $SRC_DIR.replace('\\','\')
	$SourceFiles | % { # loop through the source dir files
	    $src = $_.FullName #current source dir file
		$srcMD5 = Get-FileMD5 -file $src
		Write-Host "Source file hash: $src :: $srcMD5"
		Add-Content $File_Hash_New "$src::$srcMD5"
	}
	RETURN 1
}
Function Check-Hash
{
	Write-Host "" | Out-File $File_Hash_Check
	$SRC_DIR = $SRC_DIR.replace('\','\\')
	$SourceFiles = get-childitem -Recurse $SRC_DIR | ? { $_.PSIsContainer -eq $false} #get the files in the source dir.
	$SRC_DIR = $SRC_DIR.replace('\\','\')
	$SourceFiles | % { # loop through the source dir files
	    $src = $_.FullName #current source dir file
		$srcMD5 = Get-FileMD5 -file $src
		Write-Host "Source file hash: $src :: $srcMD5"
		Add-Content $File_Hash_Check "$src::$srcMD5"
	}
	Write-Host "[+] Check diff !!!!!!!" -ForegroundColor green
	compare-object (get-content $File_Hash_New) (get-content $File_Hash_Check)
	RETURN 1
}
####################################USAGE####################################
if ($mode -like "none")
{
	Write-Host "[+] USAGE: .\$($MyInvocation.MyCommand.Name) "
	Write-Host "    -mode <'build', 'update-hash', 'check-hash', 'remove'> "-ForegroundColor red
	Write-Host "    -File-Hash <"$"HashFile_New.log> " -ForegroundColor green
	Write-Host "    -Task_XML <OneDrive.xml> "-ForegroundColor green
	
	Write-Host "    [-] Task-Scheduler config"
	Write-Host "    -StartBoundary <2005-10-11T08:00:00>"-ForegroundColor green
	Write-Host "    -Interval <PT1M>"-ForegroundColor green
	Write-Host "    -Duration <PT4M>"-ForegroundColor green
	Write-Host "    -DaysInterval <2>"-ForegroundColor green
	Write-Host "    -AtLogon <True-False> : True is default"-ForegroundColor green
	
	Write-Host "    -SRC_DIR <C:\Users\<Username>"-ForegroundColor red
	return
}

####################################PREPARE####################################


####################################BUILD####################################
if ($mode -like "build"){
#XML for task scheduler
	Write-Host "" | Out-File $Task_XML
	Add-Content $Task_XML "<?xml version='1.0' encoding='UTF-16'?>"
	Add-Content $Task_XML "<Task version='1.2' xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>"
	Add-Content $Task_XML "  <RegistrationInfo>"
	Add-Content $Task_XML "    <Date>2015-01-27T18:30:34</Date>"
	Add-Content $Task_XML "    <Author>OneDrive</Author>"
	Add-Content $Task_XML "  </RegistrationInfo>"
	Add-Content $Task_XML "  <Triggers>"
	Add-Content $Task_XML "    <LogonTrigger>"
	Add-Content $Task_XML "      <StartBoundary>2015-01-27T19:30:00</StartBoundary>"
	Add-Content $Task_XML "      <Enabled>$AtLogon</Enabled><!--Logon-->"
	Add-Content $Task_XML "    </LogonTrigger>"
	Add-Content $Task_XML "	<CalendarTrigger>"
	Add-Content $Task_XML "      <StartBoundary>$StartBoundary</StartBoundary><!--StartBoundary-->"
	Add-Content $Task_XML "		<Repetition>"
	Add-Content $Task_XML "      <Interval>$Interval</Interval><!--Interval-->"
	Add-Content $Task_XML "      <Duration>$Duration</Duration><!--Duration-->"
	Add-Content $Task_XML "		</Repetition>"
	Add-Content $Task_XML "		<ScheduleByDay>"
	Add-Content $Task_XML "      <DaysInterval>$DaysInterval</DaysInterval><!--DaysInterval-->"
	Add-Content $Task_XML "		</ScheduleByDay>"
	Add-Content $Task_XML "	</CalendarTrigger>"
	Add-Content $Task_XML "  </Triggers>"
	Add-Content $Task_XML "  <Principals>"
	Add-Content $Task_XML "    <Principal id='Author'>"
	Add-Content $Task_XML "      <UserId>nt authority\system</UserId>"
	Add-Content $Task_XML "      <LogonType>InteractiveToken</LogonType>"
	Add-Content $Task_XML "      <RunLevel>HighestAvailable</RunLevel>"
	Add-Content $Task_XML "    </Principal>"
	Add-Content $Task_XML "  </Principals>"
	Add-Content $Task_XML "  <Settings>"
	Add-Content $Task_XML "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
	Add-Content $Task_XML "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
	Add-Content $Task_XML "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
	Add-Content $Task_XML "    <AllowHardTerminate>true</AllowHardTerminate>"
	Add-Content $Task_XML "    <StartWhenAvailable>false</StartWhenAvailable>"
	Add-Content $Task_XML "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
	Add-Content $Task_XML "    <IdleSettings>"
	Add-Content $Task_XML "      <StopOnIdleEnd>true</StopOnIdleEnd>"
	Add-Content $Task_XML "      <RestartOnIdle>false</RestartOnIdle>"
	Add-Content $Task_XML "    </IdleSettings>"
	Add-Content $Task_XML "    <AllowStartOnDemand>true</AllowStartOnDemand>"
	Add-Content $Task_XML "    <Enabled>true</Enabled>"
	Add-Content $Task_XML "    <Hidden>false</Hidden>"
	Add-Content $Task_XML "    <RunOnlyIfIdle>false</RunOnlyIfIdle>"
	Add-Content $Task_XML "    <WakeToRun>false</WakeToRun>"
	Add-Content $Task_XML "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"
	Add-Content $Task_XML "    <Priority>7</Priority>"
	Add-Content $Task_XML "  </Settings>"
	Add-Content $Task_XML "  <Actions Context='Author'>"
	Add-Content $Task_XML "    <Exec>"
	Add-Content $Task_XML "      <Command>powershell</Command><!--Action-->"
	Add-Content $Task_XML "      	<Arguments>-exec bypass -f $('"')$Local_Task\$($MyInvocation.MyCommand.Name)$('"') -mode run</Arguments>"
    Add-Content $Task_XML "    </Exec>"
	Add-Content $Task_XML "  </Actions>"
	Add-Content $Task_XML "</Task>"

#Create directory

	$Local_Task = $Local_Task.replace('\\','\')
	if ($Local_Task[-1] -like "\"){
		$Local_Task = $Local_Task+"####" -replace "\\####", ""
	}
	if (!(test-path $Local_Task)) {
		New-Item -ItemType directory -Path $Local_Task -Force 
	}
	
#Change current file
    #refresh token
$rf_Token = (Get-Content $MyInvocation.MyCommand.Name) -match '#' + '##<RefreshToken>###'
$newrf_Token = "	[String]" + '$RefreshToken' + " = '" + $RefreshToken + "', #" + "##<RefreshToken>###"
(Get-Content $MyInvocation.MyCommand.Name).replace($rf_Token, $newrf_Token) | Out-File "$Local_Task\$($MyInvocation.MyCommand.Name)"

    #SRC_DIR
$rf_src = (Get-Content "$Local_Task\$($MyInvocation.MyCommand.Name)") -match '#' + '##<SRC_DIR>###'
$newrf_src = "	[String]" + '$SRC_DIR' + " = '" + $SRC_DIR + "', #" + "##<SRC_DIR>###"
(Get-Content "$Local_Task\$($MyInvocation.MyCommand.Name)").replace($rf_src, $newrf_src) | Out-File "$Local_Task\$($MyInvocation.MyCommand.Name)"

    #DST_DIR
$rf_dst = (Get-Content "$Local_Task\$($MyInvocation.MyCommand.Name)") -match '#' + '##<DST_DIR>###'
$newrf_dst = "	[String]" + '$DST_DIR' + " = '" + $DST_DIR + "', #" + "##<DST_DIR>###"
(Get-Content "$Local_Task\$($MyInvocation.MyCommand.Name)").replace($rf_dst, $newrf_dst) | Out-File "$Local_Task\$($MyInvocation.MyCommand.Name)"

#add to task-scheduler
schtasks.exe /Delete /TN "OneDrive" /f
schtasks.exe /create /TN OneDrive /xml $Task_XML
schtasks.exe /run /TN OneDrive

}
####################################RUN####################################
if ($mode -like "update-hash"){
	Update-Hash
}
if ($mode -like "check-hash"){
	Check-Hash
}
####################################REMOVE####################################
if ($mode -like "remove")
{
}

