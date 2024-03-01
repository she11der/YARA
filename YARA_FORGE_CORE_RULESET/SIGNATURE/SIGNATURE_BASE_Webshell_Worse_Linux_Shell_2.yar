rule SIGNATURE_BASE_Webshell_Worse_Linux_Shell_2
{
	meta:
		description = "PHP Webshells Github Archive - file Worse Linux Shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "04ed7464-29d1-54b9-98ff-afc03475b220"
		date = "2023-12-05"
		modified = "2023-12-05"
		old_rule_name = "WebShell_Worse_Linux_Shell"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5861-L5878"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "64623ab1246bc8f7d256b25f244eb2b41f543e96"
		logic_hash = "6480c524213583511253ea1d37820994bba8a86f58a3775d4a9e4325725289d8"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "if( $_POST['_act'] == \"Upload!\" ) {" fullword
		$s5 = "print \"<center><h1>#worst @dal.net</h1></center>\";" fullword
		$s7 = "print \"<center><h1>Linux Shells</h1></center>\";" fullword
		$s8 = "$currentCMD = \"ls -la\";" fullword
		$s14 = "print \"<tr><td><b>System type:</b></td><td>$UName</td></tr>\";" fullword
		$s19 = "$currentCMD = str_replace(\"\\\\\\\\\",\"\\\\\",$_POST['_cmd']);" fullword

	condition:
		2 of them
}
