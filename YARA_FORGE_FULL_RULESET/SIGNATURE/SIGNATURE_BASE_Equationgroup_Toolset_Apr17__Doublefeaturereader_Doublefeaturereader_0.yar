rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__Doublefeaturereader_Doublefeaturereader_0 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "f662c961-80be-5453-86b1-c4d40ac5b732"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L3274-L3293"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9049e1fe31917ecc27e57afecd5845afcd966aac83d386b7c0995c1e3378a0d0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "052e778c26120c683ee2d9f93677d9217e9d6c61ffc0ab19202314ab865e3927"
		hash2 = "5db457e7c7dba80383b1df0c86e94dc6859d45e1d188c576f2ba5edee139d9ae"

	strings:
		$x1 = "DFReader.exe logfile AESKey [-j] [-o outputfilename]" fullword ascii
		$x2 = "Double Feature Target Version" fullword ascii
		$x3 = "DoubleFeature Process ID" fullword ascii
		$op1 = { a1 30 21 41 00 89 85 d8 fc ff ff a1 34 21 41 00 }

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them ) or (2 of them )
}
