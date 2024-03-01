rule SIGNATURE_BASE_Phpinj_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file pHpINJ.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "7bf54ef4-a3d8-51c6-8db7-bf8947e992ed"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4012-L4024"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "d7a4b0df45d34888d5a09f745e85733f"
		logic_hash = "5d39fd31cdaae7765267ce8a35a2fdcf86e7f0de40d4f303fb0f219c0fc04e40"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "News Remote PHP Shell Injection"
		$s3 = "Php Shell <br />" fullword
		$s4 = "<input type = \"text\" name = \"url\" value = \""

	condition:
		2 of them
}
