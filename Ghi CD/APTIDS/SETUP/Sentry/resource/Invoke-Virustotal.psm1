Add-Type -assembly System.Security
function Invoke-Virustotal{
	Param (
		[String] $FilePath
	)
	Begin {
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
			$properties = @{
				MD5       = $VTReport.MD5
				SHA1      = $VTReport.SHA1
				SHA256    = $VTReport.SHA256
				VTLink    = $VTReport.permalink
				VTReport  = "$($VTReport.positives)/$($VTReport.total)"
				VTMessage = $VTReport.verbose_msg
				Engines   = $AVScanFound
			}
			return $properties
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
							$properties = Query-VirusTotal -Hash (Get-Hash -FilePath $_) | Add-Member -MemberType NoteProperty -Name FilePath -Value $_ -PassThru
						}
					}
				}
				return $properties
			}
		}
	}
	Process {
		$ApiKey = "50fa776ec036589e84a35b2dd4edf9bf487f67c1ac1c97ed69eddfe82d641691"
		$properties = Get-VirusTotalReport -VTApiKey $ApiKey -FilePath $FilePath
		$properties = $properties + @{Path=$FilePath}
		return $properties
	}
	End {
    }
}
Export-ModuleMember -Function *