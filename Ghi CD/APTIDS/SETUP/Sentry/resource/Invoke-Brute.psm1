$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
function Invoke-Brute{
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
			Write-Host "" | Out-File ".\\log\\Invoke-Brute_Analysis.xlsx"
	
		}
		else{
			Write-Host "" | Out-File ".\\log\\Invoke-Brute_Report.xlsx"
			$start = (Get-Date).AddDays(-$days)
			$end = Get-Date
			
			Add-Content ".\\log\\Invoke-Brute_Report.xlsx" "RDP-REPORT`n"
			Get-EventLog -after $start -before $end "Security" | Select-Object -Property EventID, MachineName, EntryType, Message, TimeGenerated | Group-Object eventid | Sort-Object Name | ForEach-Object{
				if(($_.Name -eq "4798") -or ($_.Name -eq "4625")){
					$msg = $_.Message -replace "`r`n", ";"
					$msg = $msg -replace "`n", ""
					$msg = $msg -replace "`t", ":"
					
					$result = "RDP : $($_.Name) with $($_.Count) times"
					Add-Content ".\\log\\Invoke-EventLog_Report.xlsx" $result
				}
			}
			
			Add-Content ".\\log\\Invoke-Brute_Report.xlsx" "VNC-REPORT`n"
			Get-EventLog -after $start -before $end "Security" | Select-Object -Property EventID, MachineName, EntryType, Message, TimeGenerated | Group-Object eventid | Sort-Object Name | ForEach-Object{
				if(($_.Name -eq "258") -or ($_.Name -eq "258")){
					$msg = $_.Message -replace "`r`n", ";"
					$msg = $msg -replace "`n", ""
					$msg = $msg -replace "`t", ":"
					
					$result = "VNC : $($_.Name) with $($_.Count) times"
					Add-Content ".\\log\\Invoke-EventLog_Report.xlsx" $result
				}
			}
			
			Add-Content ".\\log\\Invoke-Brute_Report.xlsx" "SMB-REPORT`n"
			Get-EventLog -after $start -before $end "Security" | Select-Object -Property EventID, MachineName, EntryType, Message, TimeGenerated | Group-Object eventid | Sort-Object Name | ForEach-Object{
				if(($_.Name -eq "40968")){
					$msg = $_.Message -replace "`r`n", ";"
					$msg = $msg -replace "`n", ""
					$msg = $msg -replace "`t", ":"
					
					$result = "SMB : $($_.Name) with $($_.Count) times"
					Add-Content ".\\log\\Invoke-EventLog_Report.xlsx" $result
				}
			}
			
			Add-Content ".\\log\\Invoke-Brute_Report.xlsx" "Login-Local-REPORT`n"
			Get-EventLog -after $start -before $end "Security" | Select-Object -Property EventID, MachineName, EntryType, Message, TimeGenerated | Group-Object eventid | Sort-Object Name | ForEach-Object{
				if(($_.Name -eq "529") -or ($_.Name -eq "529")){
					$msg = $_.Message -replace "`r`n", ";"
					$msg = $msg -replace "`n", ""
					$msg = $msg -replace "`t", ":"
					
					$result = "Login-Local : $($_.Name) with $($_.Count) times"
					Add-Content ".\\log\\Invoke-EventLog_Report.xlsx" $result
				}
			}
			
			Add-Content ".\\log\\Invoke-Brute_Report.xlsx" "Login-Kerberos-REPORT`n"
			Get-EventLog -after $start -before $end "Security" | Select-Object -Property EventID, MachineName, EntryType, Message, TimeGenerated | Group-Object eventid | Sort-Object Name | ForEach-Object{
				if(($_.Name -eq "675") -or ($_.Name -eq "675")){
					$msg = $_.Message -replace "`r`n", ";"
					$msg = $msg -replace "`n", ""
					$msg = $msg -replace "`t", ":"
					
					$result = "Login-Kerberos : $($_.Name) with $($_.Count) times"
					Add-Content ".\\log\\Invoke-EventLog_Report.xlsx" $result
				}
			}
			
			Add-Content ".\\log\\Invoke-Brute_Report.xlsx" "Login-NTLM-REPORT`n"
			Get-EventLog -after $start -before $end "Security" | Select-Object -Property EventID, MachineName, EntryType, Message, TimeGenerated | Group-Object eventid | Sort-Object Name | ForEach-Object{
				if(($_.Name -eq "681") -or ($_.Name -eq "681")){
					$msg = $_.Message -replace "`r`n", ";"
					$msg = $msg -replace "`n", ""
					$msg = $msg -replace "`t", ":"
					
					$result = "Login-NTLM : $($_.Name) with $($_.Count) times"
					Add-Content ".\\log\\Invoke-EventLog_Report.xlsx" $result
				}
			}
		}
	}
	End {
    }
}
Export-ModuleMember -Function *