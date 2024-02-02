rule SIGNATURE_BASE_Phvayvv_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file phvayvv.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "76351a59-8f52-5110-a9b8-36edd59026df"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3818-L3830"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "35fb37f3c806718545d97c6559abd262"
		logic_hash = "503a69a7e2c30cc82eba430082627bb93c459a95f675b968126bf4524c598863"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "{mkdir(\"$dizin/$duzenx2\",777)"
		$s1 = "$baglan=fopen($duzkaydet,'w');"
		$s2 = "PHVayv 1.0"

	condition:
		1 of them
}