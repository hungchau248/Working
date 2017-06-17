$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
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
		[switch]$Analysis
	)
	Begin {
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
		function check(){
			Write-Host "23"
		}
	}
	Process {
		if($Analysis){
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
		else{
			Write-Host "" | Out-File ".\\log\\Invoke-Registry_Report.xlsx"
			Add-Content ".\\log\\Invoke-Registry_Report.xlsx" "element`tName`tExecuteFile`tExecuteFile`tDigitalSignature"
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
					Add-Content ".\\log\\Invoke-Registry_Report.xlsx" "$element`t$Name`t$ExecuteFile`t$ExecuteFile`t$DigitalSignature"
				}
			}
		}
	}
	End {
    }
}
Export-ModuleMember -Function *