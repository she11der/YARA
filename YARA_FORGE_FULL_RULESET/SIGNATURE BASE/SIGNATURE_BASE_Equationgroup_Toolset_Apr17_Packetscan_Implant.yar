rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Packetscan_Implant : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "e49695d9-15ae-53a6-955c-c68402e241a2"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2637-L2652"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "aa2106d2aad3e81c864181c851574f76f48cd4fe48bb3327135f2956d271dfde"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9b97cac66d73a9d268a15e47f84b3968b1f7d3d6b68302775d27b99a56fbb75a"

	strings:
		$op0 = { e9 ef fe ff ff ff b5 c0 ef ff ff 8d 85 c8 ef ff }
		$op1 = { c9 c2 04 00 b8 34 26 00 68 e8 40 05 00 00 51 56 }
		$op2 = { e9 0b ff ff ff 8b 45 10 8d 4d c0 89 58 08 c6 45 }

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and all of them )
}
