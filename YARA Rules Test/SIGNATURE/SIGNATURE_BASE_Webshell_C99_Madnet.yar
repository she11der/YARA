rule SIGNATURE_BASE_Webshell_C99_Madnet
{
	meta:
		description = "PHP Webshells Github Archive - file c99_madnet.php"
		author = "Florian Roth (Nextron Systems)"
		id = "f2b9c3d1-1c55-59cb-a9bf-8b4011f86a3b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5960-L5975"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "17613df393d0a99fd5bea18b2d4707f566cff219"
		logic_hash = "cd4048f28405f106302643656ae5f8a257aaec0184a8057a9dffbda9bb857027"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
		$s1 = "eval(gzinflate(base64_decode('"
		$s2 = "$pass = \"pass\";  //Pass" fullword
		$s3 = "$login = \"user\"; //Login" fullword
		$s4 = "             //Authentication" fullword

	condition:
		all of them
}