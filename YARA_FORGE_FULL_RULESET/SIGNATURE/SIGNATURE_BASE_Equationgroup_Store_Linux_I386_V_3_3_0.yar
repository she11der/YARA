rule SIGNATURE_BASE_Equationgroup_Store_Linux_I386_V_3_3_0 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "b88be148-5308-583a-b41e-2bea9b837e2a"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1018-L1033"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f284c2fecee23f01f83e0534d7d56a88b102e6dcc02a26321fe246604dc8cb0e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "abc27fda9a0921d7cf2863c29768af15fdfe47a0b3e7a131ef7e5cc057576fbc"

	strings:
		$s1 = "[-] Failed to map file: %s" fullword ascii
		$s2 = "[-] can not NULL terminate input data" fullword ascii
		$s3 = "[!] Name has size of 0!" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <60KB and all of them )
}
