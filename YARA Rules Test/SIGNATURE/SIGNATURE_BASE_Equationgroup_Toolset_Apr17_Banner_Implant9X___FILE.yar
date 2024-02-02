rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Banner_Implant9X___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "7cbb509e-2a91-5e3c-8d19-61fda797cd8c"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2114-L2129"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "5bda7b8ab097c0a5ca90b05147d4227e5a03735b99633b5081d80d2d72bceba9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5d69a8cfc9b636448f023fcf18d111f13a8e6bcb9a693eb96276e0d796ab4e0c"

	strings:
		$s1 = ".?AVFeFinallyFailure@@" fullword ascii
		$op1 = { c9 c3 57 8d 85 2c eb ff ff }

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and all of them )
}