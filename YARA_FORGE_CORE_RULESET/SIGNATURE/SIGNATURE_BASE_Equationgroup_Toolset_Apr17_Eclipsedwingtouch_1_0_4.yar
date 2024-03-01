rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Eclipsedwingtouch_1_0_4 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "87e46fcd-d3e5-506a-97f3-8a18a7ba8042"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1749-L1763"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "4707dbbb302b9b2192bdd23e4b64e25b5b2f49c3dd7951905a07cb5b54d524d9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "46da99d80fc3eae5d1d5ab2da02ed7e61416e1eafeb23f37b180c46e9eff8a1c"

	strings:
		$x1 = "[-] The target is NOT vulnerable" fullword ascii
		$x2 = "[+] The target IS VULNERABLE" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and 1 of them )
}
