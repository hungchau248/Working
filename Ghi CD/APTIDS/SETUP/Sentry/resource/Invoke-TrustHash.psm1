$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
function Invoke-TrustHash{
	Param(
		[switch]$Analysis,
		[string]$file
	)
	Begin {
		Import-Module ".\Invoke-Virustotal.psm1"
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
			Write-Host "" | Out-File ".\\log\\Invoke-TrustHash_Analysis.xlsx"
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
		else{
			Write-Host "" | Out-File ".\\log\\Invoke-TrustHash_Report.xlsx"
			
		}
	}
	End {
		Remove-Module Invoke-EventLog
    }
}
Export-ModuleMember -Function *