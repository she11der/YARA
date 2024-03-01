rule SIGNATURE_BASE_C99Madshell_V2_0_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file c99madshell_v2.0.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "b0724920-dc1e-5819-a99b-618a9a7e1eca"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3899-L3909"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "d27292895da9afa5b60b9d3014f39294"
		logic_hash = "07922511d9dfdd32f6b1f47479fca2063b773024a20dcab6f5cf4d56d66c3397"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s2 = "eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXef"

	condition:
		all of them
}
