rule SIGNATURE_BASE_Ayyildiz_Tim___AYT__Shell_V_2_1_Biz_Html
{
	meta:
		description = "Semi-Auto-generated  - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "d50a8669-fd28-59d2-9f00-f4fe2b85dc22"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4548-L4561"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "8a8c8bb153bd1ee097559041f2e5cf0a"
		logic_hash = "9e2d56b49df65a2c13e15f97ec91cdbb6852d86e86f921d7c8a4db82cbea12f5"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Ayyildiz"
		$s1 = "TouCh By iJOo"
		$s2 = "First we check if there has been asked for a working directory"
		$s3 = "http://ayyildiz.org/images/whosonline2.gif"

	condition:
		2 of them
}