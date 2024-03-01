rule SIGNATURE_BASE_Csh_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file csh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "da691516-d6c9-5c4b-85c3-f1cd7fc96ae7"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3998-L4011"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "194a9d3f3eac8bc56d9a7c55c016af96"
		logic_hash = "2a74e06a9fd59d7a577041b49403738904239fb011f9bfe2fb665165991b9c98"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = ".::[c0derz]::. web-shell"
		$s1 = "http://c0derz.org.ua"
		$s2 = "vint21h@c0derz.org.ua"
		$s3 = "$name='63a9f0ea7bb98050796b649e85481845';//root"

	condition:
		1 of them
}
