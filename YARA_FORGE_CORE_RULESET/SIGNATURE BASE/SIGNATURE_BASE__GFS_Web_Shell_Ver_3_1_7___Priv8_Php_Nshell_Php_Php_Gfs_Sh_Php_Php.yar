rule SIGNATURE_BASE__GFS_Web_Shell_Ver_3_1_7___Priv8_Php_Nshell_Php_Php_Gfs_Sh_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - from files GFS web-shell ver 3.1.7 - PRiV8.php.txt, nshell.php.php.txt, gfs_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "4d1dd87b-1ffd-564d-9411-c5d2fc01ae0f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5298-L5313"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "9df5b6df25574b303044a0799c5eb5f38f9ebfbc6f6114275fe1e34adbde1f7c"
		score = 75
		quality = 85
		tags = ""
		super_rule = 1
		hash0 = "be0f67f3e995517d18859ed57b4b4389"
		hash1 = "4a44d82da21438e32d4f514ab35c26b6"
		hash2 = "f618f41f7ebeb5e5076986a66593afd1"

	strings:
		$s2 = "echo $uname.\"</font><br><b>\";" fullword
		$s3 = "while(!feof($f)) { $res.=fread($f,1024); }" fullword
		$s4 = "echo \"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid()"

	condition:
		2 of them
}
