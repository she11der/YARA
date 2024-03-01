rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Setcallbackports : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "3c06fc74-2e75-5348-bb62-30c724de1414"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2995-L3009"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e087534589228ac1af8b8b8d2ebbc1bc99fc25b38cb4c4d840cab8e90e75644a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "16f66c2593665c2507a78f96c0c2a9583eab0bda13a639e28f550c92f9134ff0"

	strings:
		$s1 = "USAGE: %s <input file> <output file> <port1> [port2] [port3] [port4] [port5] [port6]" fullword ascii
		$s2 = "You may enter between 1 and 6 ports to change the defaults." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them )
}
