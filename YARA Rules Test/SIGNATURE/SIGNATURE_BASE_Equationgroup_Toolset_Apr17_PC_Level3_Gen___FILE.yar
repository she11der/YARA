rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_PC_Level3_Gen___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "c479964c-3122-511d-9410-bc5d890f1489"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2581-L2600"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "2ba0f5ada13bd8c71836f26e278c334fdbf2578eac189852befee7a81c07e169"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c7dd49b98f399072c2619758455e8b11c6ee4694bb46b2b423fa89f39b185a97"
		hash2 = "f6b723ef985dfc23202870f56452581a08ecbce85daf8dc7db4491adaa4f6e8f"

	strings:
		$s1 = "S-%u-%u" fullword ascii
		$s2 = "Copyright (C) Microsoft" fullword wide
		$op1 = { 24 39 65 c6 44 24 3a 6c c6 44 24 3b 65 c6 44 24 }
		$op2 = { 44 24 4e 41 88 5c 24 4f ff }
		$op3 = { 44 24 3f 6e c6 44 24 40 45 c6 44 24 41 }

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 3 of them )
}