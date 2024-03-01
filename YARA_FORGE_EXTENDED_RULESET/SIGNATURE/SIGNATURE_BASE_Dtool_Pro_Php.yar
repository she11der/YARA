rule SIGNATURE_BASE_Dtool_Pro_Php
{
	meta:
		description = "Semi-Auto-generated  - file DTool Pro.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "c02c522c-8418-5760-869a-52b41785bebc"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4755-L4767"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "366ad973a3f327dfbfb915b0faaea5a6"
		logic_hash = "e8f8b4ca2ab4607e700e897671fd230280763a70897b8ccfc31b3bcb7f2a1f4a"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "r3v3ng4ns\\nDigite"
		$s1 = "if(!@opendir($chdir)) $ch_msg=\"dtool: line 1: chdir: It seems that the permissi"
		$s3 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n"

	condition:
		1 of them
}
