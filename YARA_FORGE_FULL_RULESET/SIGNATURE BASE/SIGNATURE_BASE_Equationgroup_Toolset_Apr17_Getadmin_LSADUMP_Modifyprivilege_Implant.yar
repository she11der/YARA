rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Getadmin_LSADUMP_Modifyprivilege_Implant : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "b3fda153-563c-5a5c-9f5c-12d6ef8b3d95"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2860-L2882"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ee5c818c29ccb1b280669f7f5e828963c4523b73b68674d8c0aae72189f0208c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c8b354793ad5a16744cf1d4efdc5fe48d5a0cf0657974eb7145e0088fcf609ff"
		hash2 = "5f06ec411f127f23add9f897dc165eaa68cbe8bb99da8f00a4a360f108bb8741"

	strings:
		$s1 = "\\system32\\win32k.sys" wide
		$s2 = "hKeAddSystemServiceTable" fullword ascii
		$s3 = "hPsDereferencePrimaryToken" fullword ascii
		$s4 = "CcnFormSyncExFBC" fullword wide
		$s5 = "hPsDereferencePrimaryToken" fullword ascii
		$op1 = { 0c 2b ca 8a 04 11 3a 02 75 01 47 42 4e 75 f4 8b }
		$op2 = { 14 83 c1 05 80 39 85 75 0c 80 79 01 c0 75 06 80 }
		$op3 = { eb 3d 83 c0 06 33 f6 80 38 ff 75 2c 80 78 01 15 }

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and (4 of ($s*) or all of ($op*)))
}
