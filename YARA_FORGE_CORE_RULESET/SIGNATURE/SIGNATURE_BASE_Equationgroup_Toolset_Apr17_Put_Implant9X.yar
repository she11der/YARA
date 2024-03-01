rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Put_Implant9X : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "73cafd51-8b0d-59e3-966d-2f5de65953a7"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2602-L2618"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e79a59e400aac544dc1160d5898e3053f88f7d5bc142440177526187650484e7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8fcc98d63504bbacdeba0c1e8df82f7c4182febdf9b08c578d1195b72d7e3d5f"

	strings:
		$s1 = "3&3.3<3A3F3K3V3c3m3" fullword ascii
		$op1 = { c9 c2 08 00 b8 72 1c 00 68 e8 c9 fb ff ff 51 56 }
		$op2 = { 40 1b c9 23 c8 03 c8 38 5d 14 74 05 6a 03 58 eb }

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and 2 of them )
}
