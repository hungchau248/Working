$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
function Invoke-EventLog{
	Param(
		[switch]$Analysis,
		[int]$days
		
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
			Write-Host "" | Out-File ".\\log\\Invoke-EventLog_Analysis.xlsx"
			$start = (Get-Date).AddDays(-$days)
			$end = Get-Date
			$result = Get-EventLog -after $start -before $end "Security" | Select-Object -Property EventID, MachineName, EntryType, Message, TimeGenerated | Group-Object eventid | Sort-Object Name
		}
		else{
			Write-Host "" | Out-File ".\\log\\Invoke-EventLog_Report.xlsx"
			Add-Content ".\\log\\Invoke-EventLog_Report.xlsx" "SECURITY-REPORT`n"
			$start = (Get-Date).AddDays(-$days)
			$end = Get-Date
			Get-EventLog -Newest 10 "Security" | ForEach-Object{
				$msg = $_.Message -replace "`r`n", ";"
				$msg = $msg -replace "`n", ""
				$msg = $msg -replace "`t", ":"
				
				$result = "$($_.EventID)`t$($_.MachineName)`t$($_.EntryType)`t$($TimeGenerated)`t$($msg)"
				Add-Content ".\\log\\Invoke-EventLog_Report.xlsx" $result
			}
			
			Add-Content ".\\log\\Invoke-EventLog_Report.xlsx" "APPLICATION -REPORT`n"
			$start = (Get-Date).AddDays(-$days)
			$end = Get-Date
			Get-EventLog -Newest 10 "Application" | ForEach-Object{
				$msg = $_.Message -replace "`r`n", ";"
				$msg = $msg -replace "`n", ""
				$msg = $msg -replace "`t", ":"
				$result = "$($_.EventID)`t$($_.MachineName)`t$($_.EntryType)`t$($TimeGenerated)`t$($msg)"
				Add-Content ".\\log\\Invoke-EventLog_Report.xlsx" $result
			}
			
			Add-Content ".\\log\\Invoke-EventLog_Report.xlsx" "SYSTEM -REPORT`n"
			$start = (Get-Date).AddDays(-$days)
			$end = Get-Date
			Get-EventLog -Newest 10 "System" | ForEach-Object{
				$msg = $_.Message -replace "`r`n", ";"
				$msg = $msg -replace "`n", ""
				$msg = $msg -replace "`t", ":"
				$result = "$($_.EventID)`t$($_.MachineName)`t$($_.EntryType)`t$($TimeGenerated)`t$($msg)"
				Add-Content ".\\log\\Invoke-EventLog_Report.xlsx" $result
			}
		}
	}
	End {
    }
}
Export-ModuleMember -Function *
