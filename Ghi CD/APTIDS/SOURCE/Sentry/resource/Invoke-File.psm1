$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
function Invoke-File{
	param(
		[String]$File_Hash_New = ".\log\HashFile_New.log",
		[String]$File_Hash_Check = ".\log\HashFile_Check.log",
		[String]$mode = "none",
		[String]$SRC_DIR = "C:\Users\Binh1\Desktop",
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

		function Update-Hash
		{
			Write-Host "" | Out-File $File_Hash_New
			$SRC_DIR = $SRC_DIR.replace('\','\\')
			$SourceFiles = get-childitem -Recurse $SRC_DIR | ? { $_.PSIsContainer -eq $false} #get the files in the source dir.
			$SRC_DIR = $SRC_DIR.replace('\\','\')
			$SourceFiles | % { # loop through the source dir files
				$src = $_.FullName #current source dir file
				$srcMD5 = Get-FileMD5 -file $src
				$hashresult += "$src`t$srcMD5`n"
				Add-Content $File_Hash_New "$src::$srcMD5"
			}
			RETURN $hashresult
		}
		function Check-Hash
		{
			Write-Host "" | Out-File $File_Hash_Check
			$SRC_DIR = $SRC_DIR.replace('\','\\')
			$SourceFiles = get-childitem -Recurse $SRC_DIR | ? { $_.PSIsContainer -eq $false} #get the files in the source dir.
			$SRC_DIR = $SRC_DIR.replace('\\','\')
			$SourceFiles | % { # loop through the source dir files
				$src = $_.FullName #current source dir file
				$srcMD5 = Get-FileMD5 -file $src
				Add-Content $File_Hash_Check "$src::$srcMD5"
			}
			# Write-Host "Check diff !!!!!!!"
			$result = compare-object (get-content $File_Hash_New) (get-content $File_Hash_Check)
			RETURN $result
		}
	}
	Process {
		if($Analysis){
			Write-Host "" | Out-File ".\\log\\Invoke-File_Analysis.xlsx"
			$result= Check-Hash
			Add-Content ".\\log\\Invoke-File_Analysis.xlsx" "InputObject`tSideIndicator"
			
			$result | ForEach-Object{
				Write-Host "$($_.InputObject)`t$($_.SideIndicator)" | Out-File ".\\log\\Invoke-File_Analysis.xlsx"
			}
			Update-Hash
		}
		else{
			Write-Host "" | Out-File ".\\log\\Invoke-File_Report.xlsx"
			$result= Check-Hash
			Add-Content ".\\log\\Invoke-File_Report.xlsx" "InputObject`tSideIndicator"
			$result | ForEach-Object{
				Add-Content ".\\log\\Invoke-File_Report.xlsx" "$($_.InputObject)`t$($_.SideIndicator)"
			}
			
			Add-Content ".\\log\\Invoke-File_Report.xlsx" "`nPath`tMD5"
			$hashresult = Update-Hash
			Add-Content ".\\log\\Invoke-File_Report.xlsx" $hashresult
		}
	}
	End {
    }
}
Export-ModuleMember -Function *