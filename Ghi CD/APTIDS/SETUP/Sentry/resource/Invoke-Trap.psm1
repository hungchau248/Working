$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
function Invoke-Trap{
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
			$reg = $((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name NtfsDisableLastAccessUpdate).NtfsDisableLastAccessUpdate)
			if($reg -eq 1){
				PS C:\Windows\system32> Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name NtfsDisableLastAccessUpdate  -Type DWORD -Value "0"
			}
		}
	}
	Process {
		if($Analysis){
			Write-Host "" | Out-File ".\\log\\Invoke-Trap_Analysis.xlsx"
		}
		else{
			Write-Host "" | Out-File ".\\log\\Invoke-Trap_Report.xlsx"
			$ret = $(Get-ChildItem c:\pass -File | select name, *time)

		}
	}
	End {
    }
}
Export-ModuleMember -Function *