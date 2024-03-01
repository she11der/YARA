rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Diba_Target_BH : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "c6ae85b6-0670-558c-9ce5-64bd5822f35b"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2477-L2492"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "273e38e287b1597753f653c0ed8300936581a1b767029d3f0ba757de589bcd5a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7ae9a247b60dc31f424e8a7a3b3f1749ba792ff1f4ba67ac65336220021fce9f"

	strings:
		$op0 = { 44 89 20 e9 40 ff ff ff 8b c2 48 8b 5c 24 60 48 }
		$op1 = { 45 33 c9 49 8d 7f 2c 41 ba }
		$op2 = { 89 44 24 34 eb 17 4c 8d 44 24 28 8b 54 24 30 48 }

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
