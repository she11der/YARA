rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Esteemaudit_2_1_0 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "95594756-1872-5d86-877f-0977bd3c067b"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1571-L1585"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "272d435758c0021bfd84d84c00eb05ece2461a39d092693b61d362365ab098cd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "61f98b12c52739647326e219a1cf99b5440ca56db3b6177ea9db4e3b853c6ea6"

	strings:
		$x1 = "[+] Connected to target %s:%d" fullword ascii
		$x2 = "[-] build_exploit_run_x64():" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
