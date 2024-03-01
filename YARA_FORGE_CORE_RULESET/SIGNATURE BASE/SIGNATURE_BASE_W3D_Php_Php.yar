rule SIGNATURE_BASE_W3D_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file w3d.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "1a4e3c84-2d3b-5245-bccc-9a5f59b9fc17"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3947-L3959"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "987f66b29bfb209a0b4f097f84f57c3b"
		logic_hash = "33f948a1ae4474daddd788df84fa8baabf4390ec242cad9a6a51dac0152d3b75"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "W3D Shell"
		$s1 = "By: Warpboy"
		$s2 = "No Query Executed"

	condition:
		2 of them
}
