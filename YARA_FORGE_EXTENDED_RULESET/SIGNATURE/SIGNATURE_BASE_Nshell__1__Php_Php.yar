rule SIGNATURE_BASE_Nshell__1__Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file Nshell (1).php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "44e8b6c5-6f41-5c37-a083-26acedd91956"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L3657-L3668"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "973fc89694097a41e684b43a21b1b099"
		logic_hash = "53c7cd24c4eddbded1b4c16fd2758bdf66c0bbe396e487a56d56fc053cf3cc1a"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "echo \"Command : <INPUT TYPE=text NAME=cmd value=\".@stripslashes(htmlentities($"
		$s1 = "if(!$whoami)$whoami=exec(\"whoami\"); echo \"whoami :\".$whoami.\"<br>\";" fullword

	condition:
		1 of them
}
