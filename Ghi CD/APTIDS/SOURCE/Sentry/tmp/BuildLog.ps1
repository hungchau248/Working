$ErrorActionPreference= 'silentlycontinue'
function Invoke-ScheduledTask{
	Param(
		[String]$TaskName,
		[String]$TaskPath,
		[String]$State,
		[String]$Author,
		[String]$Description,
		[String]$Triggers,
		[String]$ExecuteFile,
		[String]$Arguments,
		[String]$DigitalSignature
	)
	Write-Host "" | Out-File "log"
	Get-ScheduledTask | ForEach-Object {
		$TaskName = $_.TaskName
		$TaskPath = $_.TaskPath
		$State = $_.State
		$Author = $_.Author
		$Description = $_.Description
		$Triggers = $_.Triggers
		$ExecuteFile = $_.Actions.Execute
		$Arguments = $_.Actions.Arguments
		$DigitalSignature = ""
		
		$ExecuteFile = Resolve-Path $ExecuteFile 
		if($ExecuteFile -ne ""){
			try{
				$DigitalSignature = $(Get-AuthenticodeSignature $ExecuteFile).Status
			}
			Catch{}
			
		}
		if($DigitalSignature -ne "Valid" -and $ExecuteFile -ne ""){
			Write-Host "$ExecuteFile : $DigitalSignature"
			# interact with virus total
		}
	}
}
function Invoke-Service{
	Param(
		[String]$Name,
		[String]$DisplayName,
		[String]$Status,
		[String]$ProcessId,
		[String]$PathName ,
		[String]$ExecuteFile,
		[String]$Arguments,
		[String]$DigitalSignature
	)
	Write-Host "" | Out-File "log"
	gwmi win32_service	 | ForEach-Object {
		$Name = $_.Name
		$DisplayName = $_.DisplayName
		$Status = $_.Status
		$ProcessId = $_.ProcessId
		$PathName = $_.PathName
		$DigitalSignature = ""
		
		if($PathName -ne ""){
			if($PathName[0] -eq '"'){
				$ExecuteFile = $PathName.Split('"')[1]
				$Arguments = Join-String $PathName.Split('"')[1][2..100] " "
			}
			else{
				$ExecuteFile = $PathName.Split(" ")[0]	
				$Arguments = Join-String $PathName.Split(" ")[1..100] " "
			}
		}
		$ExecuteFile = Resolve-Path $ExecuteFile 
		if($ExecuteFile -ne ""){
			try{
				$DigitalSignature = $(Get-AuthenticodeSignature $ExecuteFile).Status
			}
			Catch{}
			
		}
		if($DigitalSignature -ne "Valid" -and $ExecuteFile -ne ""){
			Write-Host "$ExecuteFile : $DigitalSignature"
			# interact with virus total
		}
	}
}
function Invoke-File{
	param(
		[String]$File_Hash_New = "HashFile_New.log",
		[String]$File_Hash_Check = "HashFile_Check.log",
		[String]$mode = "none",
		[String]$SRC_DIR = "C:\Users\Binh1\Desktop"
	)
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
	if ($mode -like "update-hash"){
		Update-Hash
	}
	if ($mode -like "check-hash"){
		Check-Hash
	}
	
}
function Invoke-Registry{
	Param(
		$ItemProperty = @("hklm:\Software\Microsoft\Windows\CurrentVersion\Run",
			"hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
			"hklm:\Software\Microsoft\Windows\CurrentVersion\RunServices",
			"hklm:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
			"hklm:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
			"hkcu:\Software\Microsoft\Windows\CurrentVersion\Run",
			"hkcu:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
			"hkcu:\Software\Microsoft\Windows\CurrentVersion\RunServices",
			"hkcu:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
			"hkcu:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
		),
		[String]$Name,
		[String]$ExecuteFile,
		[String]$Arguments,
		[String]$DigitalSignature
	)
	foreach ($element in $ItemProperty){
		[String]$result = Get-ItemProperty $element
		$tmp = $result.length - 2
		$result = -join $result[2..$tmp]
		$result1 = $result.split(';')
		foreach ($item in $result1){
			# Write-Host $item
			$DigitalSignature = ""
			if($item[0] -eq " "){
				$item = -join $item[1..1000]
			}
			$item = $item.split('=')	
			$Name = $item[0]
			if($item[1] -ne ""){
				if($item[1][0] -eq '"'){
					$ExecuteFile = $item[1].Split('"')[1]
					$Arguments = Join-String $item[1].Split('"')[2..100] " "
				}
				else{
					$pos = $item[1].IndexOf(".exe")
					$ExecuteFile = $item[1].Substring(0, $pos+4)
					$Arguments = $item[1].Substring($pos+5)
				}
				# Write-Host $ExecuteFile
				# Write-Host $Arguments
			}
			if($ExecuteFile -ne ""){
				try{
					$DigitalSignature = $(Get-AuthenticodeSignature $ExecuteFile).Status
				}
				Catch{}
				
			}
			# Write-Host "$ExecuteFile : $DigitalSignature"
			if($DigitalSignature -ne "" -and $ExecuteFile -ne ""){
				Write-Host "$ExecuteFile : $DigitalSignature"
				# interact with virus total
			}
		}
	}
}
function Invoke-Process{} #upload, download, signature,
function Invoke-Port{}
#function Invoke-WebShell
#function Invoke-Macro
function Invoke-Virustotal{
	Add-Type -assembly System.Security
	Param (
		[Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='byPath')]
		[Alias('Path', 'FullName')]
		[String[]] $FilePath
	)
	Begin {
        $MyScriptBlock = {
			Add-Type -assembly System.Security
			function Get-Hash() {

				param([string] $FilePath)
				
				$fileStream = [System.IO.File]::OpenRead($FilePath)
				$hash = ([System.Security.Cryptography.HashAlgorithm]::Create('SHA256')).ComputeHash($fileStream)
				$fileStream.Close()
				$fileStream.Dispose()
				[System.Bitconverter]::tostring($hash).replace('-','')
			}
			function Query-VirusTotal {

				param([string]$Hash)
				
				$body = @{ resource = $hash; apikey = $VTApiKey }
				$VTReport = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $body
				$AVScanFound = @()

				if ($VTReport.positives -gt 0) {
					foreach($scan in ($VTReport.scans | Get-Member -type NoteProperty)) {
						if($scan.Definition -match "detected=(?<detected>.*?); version=(?<version>.*?); result=(?<result>.*?); update=(?<update>.*?})") {
							if($Matches.detected -eq "True") {
								$AVScanFound += "{0}({1}) - {2}" -f $scan.Name, $Matches.version, $Matches.result
							}
						}
					}
				}

				New-Object –TypeName PSObject -Property ([ordered]@{
					MD5       = $VTReport.MD5
					SHA1      = $VTReport.SHA1
					SHA256    = $VTReport.SHA256
					VTLink    = $VTReport.permalink
					VTReport  = "$($VTReport.positives)/$($VTReport.total)"
					VTMessage = $VTReport.verbose_msg
					Engines   = $AVScanFound
				})
			}


			function Get-VirusTotalReport {
				
				Param (
					[Parameter(Mandatory=$true, Position=0)]
					[String]$VTApiKey,

					[Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true, ParameterSetName='byHash')]
					[String[]] $Hash,

					[Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='byPath')]
					[Alias('Path', 'FullName')]
					[String[]] $FilePath
					)

				Process {
					
					switch ($PsCmdlet.ParameterSetName) {
						'byHash' {
							$Hash | ForEach-Object {
								Query-VirusTotal -Hash $_
							}
						}
					
						'byPath' {
							$FilePath | ForEach-Object {
								Query-VirusTotal -Hash (Get-Hash -FilePath $_) | 
									Add-Member -MemberType NoteProperty -Name FilePath -Value $_ -PassThru
							}
						}
					}
				}
			}


	}
	Process {
		$ApiKey = "50fa776ec036589e84a35b2dd4edf9bf487f67c1ac1c97ed69eddfe82d641691"
		Get-VirusTotalReport -VTApiKey $ApiKey -FilePath $FilePath
	}
	End {
        Write-Host "Done."
    }
}

# function Invoke-Bruteforce
# function Invoke-AuthLogon
# function Invoke-MonitorNetwork
# function Invoke-TrustHash
# function Invoke-DumpMemory

function Resolve-Path(){
	Param([String]$Path)
	$Path = $Path.ToLower()
	$Path = $Path.replace('"','')
	$Path = $Path.replace('%windir%','c:\windows')
	$Path = $Path.replace('%systemroot%','c:\windows')
	$Path = $Path.replace('%programfiles%','c:\program files')
	$Path = $Path.replace('%comspec%','c:\windows\system32\cmd.exe')
	# $Path = $Path.replace('"','')
	# $Path = $Path.replace('"','')
	# $Path = $Path.replace('"','')
	# $Path = $Path.replace('"','')
	
	return $Path
}

function Join-String{ 
	Param(   
		[string[]] $list,
		[string] $separator = ',',
		[switch] $Collapse
	)
	[string] $string = ''
	$first  =  $true
	if ( $list.count -ne 0 ) {
		$input = $list
	}
	 
	foreach ( $element in $input  ) {
		if ( $Collapse -and [string]::IsNullOrEmpty( $element)  ) {
			continue
		}
	 
		if ($first) {
			$string = $element
			$first  = $false
		}
		else {
			$string += $separator + $element
		}
	}							
	return $string
}


Invoke-Virustotal "C:\\Users\\Binh1\\Desktop\\APT-Research\\log"