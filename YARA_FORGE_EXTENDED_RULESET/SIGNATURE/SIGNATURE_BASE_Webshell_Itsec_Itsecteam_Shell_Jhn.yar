rule SIGNATURE_BASE_Webshell_Itsec_Itsecteam_Shell_Jhn
{
	meta:
		description = "Web Shell - from files itsec.php, itsecteam_shell.php, jHn.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L2092-L2109"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "2775d7e47a26e06ea716bdca32a0f768eccf4d269caa3d107b4a78f8684ce741"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "8ae9d2b50dc382f0571cd7492f079836"
		hash1 = "bd6d3b2763c705a01cc2b3f105a25fa4"
		hash2 = "40c6ecf77253e805ace85f119fe1cebb"

	strings:
		$s4 = "echo $head.\"<font face='Tahoma' size='2'>Operating System : \".php_uname().\"<b"
		$s5 = "echo \"<center><form name=client method='POST' action='$_SERVER[PHP_SELF]?do=db'"

	condition:
		all of them
}
