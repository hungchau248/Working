$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
function Invoke-Webshell{
	Param(
		[switch]$Analysis,
		switch]$Security,
		switch]$Analysis,
		switch]$Analysis
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
			Write-Host "" | Out-File ".\\log\\Invoke-Webshell_Analysis.xlsx"
	
		}
		else{
			if($Security){
				Write-Host "" | Out-File ".\\log\\Invoke-Webshell_Report.xlsx"
				Get-ChildItem "C:\Users\Binh1\Desktop" -Filter "*.asp?" -Recurse | Select-String -pattern "cmd.exe", "powershell.exe", "kikicoco", "phpemailer", "cmd", "noname", "hiddenshell", "s72shell", "cocacola_shell", "shell_uploader", "lamashell", "jackal", "cshell", "troyan", "b374k", "phpshell", "filesman", "cyberspy5", "spam_trustapp", "arab_black_hat", "indishell", "savefile", "gnyshell", "hackerps", "phpfilemanager", "joomla_spam", "elmaliseker", "irc_bot", "teamsql", "pbot", "antisecshell", "951078biJ", "nstview", "unitxshell", "phpspy", "getlinks", "imhapftp", "stressbypass", "darkshell", "configspy", "isko", "worse", "zaco", "mysql", "server_config", "crystal", "c99", "ahlisyurga_shell", "batavi4", "blindshell", "r3laps3", "w3dshell", "albanianshell", "hostdevil", "420532shell", "php_mailer", "udpflooder", "egyspider", "629788tryag", "efso2", "phantasma", "ajan", "ipays777", "safemode", "r57", "mahkeme", "rootshell", "clearshell", "lizozim", "ironshell", "al-marhum", "lolipop", "phpbackdoor", "devilzshell", "ajax_command_shell", "nshell", "connectback2", "king511", "cristercorp_infocollector", "dc3shell", "pzadv", "O0O", "aZRaiL", "stunshell", "perlbot", "harauku", "metasploit", "c100", "webmysql", "backdoor", "simshell", "myshell", "ntdaddy", "tdshell", "dxshell", "spyshell", "hacker", "c2007", "indexer", "webroot", "FaTaLisTiCz", "fx0", "gscshell", "kadotshell", "kaushell", "madspot", "telnet", "foreverpp", "antichat_shell", "smartshell", "webadmin", "bogel_shell", "erne", "moroccan_spam", "cmos_clr", "rhtool", "brute_force_tool", "sec4ever", "webshell", "mrtiger", "empo", "v0ld3m0r", "us3rspl", "m1n1shell", "cpanel", "symlink", "constance", "nixshell", "teamps", "remoteview", "simple_shell", "sempak", "powerdreamshell", "networkfilemanager", "cgitelnet", "snipershell", "gammashell", "variables", "nccshell", "sincap", "wordpress_exploit", "simattacker", "tryag", "fatalshell", "g00nshell", "wacking", "mildnet", "cybershell", "cbot", "devil", "sroshell", "shell_commander", "buckethead", "fuckphpshell", "ayyildiz_tim", "includeshell", "dtool", "andr3a", "backup", "nogrodpBot", "mulcishell", "orbshell", "onboomshell", "ctt_shell", "scanner_jatimcrew", "rader", "nexpl0rer", "goon", "fenix", "itsecteam_shell", "locusshell", "gohack_powerserver", "shellbot", "shell_exploit", "akatsuki", "coderz", "priv8_scr", "accept_language", "shellatildi", "1n73ction", "cgi-shell", "remoteshell", "gaulircbot", "diveshell", "reverse_shell", "mohajer22", "phpmyadmin_exploit", "empixcrew", "winx", "entrika", "b64shell", "backdoorconnect", "n3fa5t1ca", "iframe", "120667kk", "xinfo", "blood3rpriv8", "stakershell", "klasvayv", "phvayv", "zorro", "i47", "lostdc", "ekin0x", "zehir4", "obet", "h4ntu", "asmodeus", "shellarchive", "mysql_adminer", "loadshell", "perlwebshell", "extplorer", "casus15", "filesman"  |  Format-Table Path, Matches -Autosize | Out-String -Width 1024
			}
		}
	}
	End {
    }
}
Export-ModuleMember -Function *