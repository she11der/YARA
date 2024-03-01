rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Pwd_Implant : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "69d071f0-7214-5972-805a-3c0c1d2346c2"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L3161-L3176"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f565c42781ff4b0b37e7c00673fb2da2877018317cd415bdb47d4e019485c727"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ee72ac76d82dfec51c8fbcfb5fc99a0a45849a4565177e01d8d23a358e52c542"

	strings:
		$s1 = "7\"7(7/7>7O7]7o7w7" fullword ascii
		$op1 = { 40 50 89 44 24 18 FF 15 34 20 00 }

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and 1 of them )
}
