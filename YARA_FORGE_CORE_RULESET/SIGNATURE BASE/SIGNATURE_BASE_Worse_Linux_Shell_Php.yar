rule SIGNATURE_BASE_Worse_Linux_Shell_Php
{
	meta:
		description = "Semi-Auto-generated  - file Worse Linux Shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "e223e2a9-7c7a-597a-8b90-a63ee11805ea"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4485-L4496"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "8338c8d9eab10bd38a7116eb534b5fa2"
		logic_hash = "47801296b700e85f9e08857eb06f845ef8ed3f88b7d0de34d4b7c47cef6cc7fb"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "print \"<tr><td><b>Server is:</b></td><td>\".$_SERVER['SERVER_SIGNATURE'].\"</td"
		$s2 = "print \"<tr><td><b>Execute command:</b></td><td><input size=100 name=\\\"_cmd"

	condition:
		1 of them
}
