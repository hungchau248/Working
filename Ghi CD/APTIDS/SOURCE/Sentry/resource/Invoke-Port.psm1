$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
function Invoke-Port{
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
		function Get-NetworkStatistics
		{
			$properties = 'Protocol','LocalAddress','LocalPort'
			$properties += 'RemoteAddress','RemotePort','State','ProcessName','PID'

			netstat -ano | Select-String -Pattern "\s+(TCP|UDP)" | ForEach-Object {

				$item = $_.line.split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)

				if($item[1] -notmatch '^\[::')
				{           
					if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6')
					{
					   $localAddress = $la.IPAddressToString
					   $localPort = $item[1].split('\]:')[-1]
					}
					else
					{
						$localAddress = $item[1].split(':')[0]
						$localPort = $item[1].split(':')[-1]
					} 

					if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6')
					{
					   $remoteAddress = $ra.IPAddressToString
					   $remotePort = $item[2].split('\]:')[-1]
					}
					else
					{
					   $remoteAddress = $item[2].split(':')[0]
					   $remotePort = $item[2].split(':')[-1]
					} 

					New-Object PSObject -Property @{
						PID = $item[-1]
						ProcessName = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name
						Protocol = $item[0]
						LocalAddress = $localAddress
						LocalPort = $localPort
						RemoteAddress =$remoteAddress
						RemotePort = $remotePort
						State = if($item[0] -eq 'tcp') {$item[3]} else {$null}
					} | Select-Object -Property $properties
				}
			}
		}

	}
	Process {
		if($Analysis){
			Write-Host "" | Out-File ".\\log\\Invoke-Port_Analysis.xlsx"
		}
		else{
			Write-Host "" | Out-File ".\\log\\Invoke-Port_Report.xlsx"
			Get-NetworkStatistics |  ForEach-Object {
				Add-Content ".\\log\\Invoke-Port_Report.xlsx" "$($_.Protocol)`t$($_.LocalAddress)`t$($_.LocalPort)`t$($_.RemoteAddress)`t$($_.RemotePort)`t$($_.State)`t$($_.ProcessName)`t$($_.PID)"
			} 
		}
	}
	End {
    }
}
Export-ModuleMember -Function *