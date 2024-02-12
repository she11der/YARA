rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Setports___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "6dc67951-714e-57d9-b34a-0006348b6b10"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2654-L2668"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "b2c61f6ca2d59d5e596e7c5c87ed3476d957763daeaf41e6f356bacf26415faf"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "722d3cf03908629bc947c4cca7ce3d6b80590a04616f9df8f05c02de2d482fb2"

	strings:
		$s1 = "USAGE: SetPorts <input file> <output file> <version> <port1> [port2] [port3] [port4] [port5]" fullword ascii
		$s2 = "Valid versions are:  1 = PC 1.2   2 = PC 1.2 (24 hour)" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}