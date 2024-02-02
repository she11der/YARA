rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Tacothief___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "7be7ca05-c2c7-5a7d-8b1b-e6741b4397b9"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2185-L2198"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "565d94ac0dd65de0926d11ae08ee78f14dcb211ca97c77c39f394fb36890fc6f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c71953cc84c27dc61df8f6f452c870a7880a204e9e21d9fd006a5c023b052b35"

	strings:
		$x1 = "File too large!  Must be less than 655360 bytes." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}