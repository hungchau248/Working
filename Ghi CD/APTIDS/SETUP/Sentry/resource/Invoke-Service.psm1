$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
function Invoke-Service{
	Param(
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
			Write-Host "" | Out-File ".\\log\\Invoke-Service_Analysis.xlsx"
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
		else{
			Write-Host "" | Out-File ".\\log\\Invoke-Service_Report.xlsx"
			Add-Content ".\\log\\Invoke-Service_Report.xlsx" "Name`tDisplayName`tStatus`tVirusTotal`tProcessId`tPathName`tExecuteFile`tArguments`tDigitalSignature"
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
						$av = Invoke-Virustotal $ExecuteFile
					}
					Catch{}
					
				}
				
				Add-Content ".\\log\\Invoke-Service_Report.xlsx" "$Name`t$DisplayName`t$Status`t$($av.VTReport)`t$ProcessId`t$PathName`t$ExecuteFile`t$Arguments`t$DigitalSignature"
			}
		}
	}
	End {
    }
}
Export-ModuleMember -Function *