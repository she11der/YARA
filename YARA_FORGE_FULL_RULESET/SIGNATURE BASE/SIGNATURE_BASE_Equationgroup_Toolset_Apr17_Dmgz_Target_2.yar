rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Dmgz_Target_2 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "426e982c-2380-5801-ba80-ab25ec4c0f74"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2899-L2916"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ab9ab949ee17655e424f6a65d3605e9900d214d1c620e051104762d5c214419f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "55ac29b9a67e0324044dafaba27a7f01ca3d8e4d8e020259025195abe42aa904"

	strings:
		$s1 = "\\\\.\\%ls" fullword ascii
		$op0 = { e8 ce 34 00 00 b8 02 00 00 f0 e9 26 02 00 00 48 }
		$op1 = { 8b 4d 28 e8 02 05 00 00 89 45 34 eb 07 c7 45 34 }
		$op2 = { e8 c2 34 00 00 90 48 8d 8c 24 00 01 00 00 e8 a4 }

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
