$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
function Invoke-Process{
	Param(
		[switch]$Analysis
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
			Write-Host "" | Out-File ".\\log\\Invoke-Process_Analysis.xlsx"
		}
		else{
			Write-Host "" | Out-File ".\\log\\Invoke-Process_Report.xlsx"
			Get-Process |  ForEach-Object {
				$ProcessName = $_.ProcessName
				$Id = $_.Id
				$StartTime = $_.StartTime
				$Modules = $_.Modules 
				$Path = $_ | Select-Object -ExpandProperty Path
				
				$Modules = $Modules -join "; "
				$Modules = $Modules.replace("System.Diagnostics.ProcessModule (","")
				$Modules = $Modules.replace(")","")
				$DigitalSignature = $(Get-AuthenticodeSignature $Path).Status
				$AV = ($(Invoke-Virustotal -FilePath $Path).VTReport)
				# Write-Host $DigitalSignature
				# Write-Host $AV
				Add-Content ".\\log\\Invoke-Process_Report.xlsx" "$ProcessName`t$Id`t$StartTime`t$Path`t$DigitalSignature`t$AV`t$Modules`t"
				# Write-Host "$ProcessName`t$Id`t$StartTime`t$Path`t$Modules`t"
			} 
		}
	}
	End {
    }
}
Export-ModuleMember -Function *