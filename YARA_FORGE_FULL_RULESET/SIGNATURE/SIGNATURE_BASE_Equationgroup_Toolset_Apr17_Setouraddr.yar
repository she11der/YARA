rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Setouraddr : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "a2dbfa7b-3fb6-56cf-9391-1a3abb08e3cb"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2844-L2858"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d49bcef48afeb63b763c88443930f28be1d6f9f27d5f0bd9161d151fa3081868"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "04ccc060d401ddba674371e66e0288ebdbfa7df74b925c5c202109f23fb78504"

	strings:
		$s1 = "USAGE: SetOurAddr <input file> <output file> <protocol> [IP/IPX address]" fullword ascii
		$s2 = "Replaced default IP address (127.0.0.1) with Local IP Address %d.%d.%d.%d" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them )
}
