rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Ntevt : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "fd25f703-ff3e-5e75-b1eb-24a658a1ac8e"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2200-L2219"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "29572cce9af51adf12db019f885f868fd77ff9034a6944a6286a4d2a0988842a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4254ee5e688fc09bdc72bcc9c51b1524a2bb25a9fb841feaf03bc7ec1a9975bf"

	strings:
		$x1 = "c:\\ntevt.pdb" fullword ascii
		$s1 = "ARASPVU" fullword ascii
		$op1 = { 41 5a 41 59 41 58 5f 5e 5d 5a 59 5b 58 48 83 c4 }
		$op2 = { f9 48 03 fa 48 33 c0 8a 01 49 03 c1 49 f7 e0 88 }
		$op3 = { 01 41 f6 e0 49 03 c1 88 01 48 33 }

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and $x1 or 3 of them )
}
