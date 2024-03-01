rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_PC_LP : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "c3f8f0f9-80ab-5d8e-be42-59b90dc291cb"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2494-L2508"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "cd7b92f13e0a00d23baef70e38b476b62394106dfa70e831786f398c573aa744"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3a505c39acd48a258f4ab7902629e5e2efa8a2120a4148511fe3256c37967296"

	strings:
		$s1 = "* Failed to get connection information.  Aborting launcher!" fullword wide
		$s2 = "Format: <command> <target port> [lp port]" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
