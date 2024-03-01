rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Remoteexecute_Target : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "608e5244-2d3f-573c-a0de-44637051f4ba"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2329-L2345"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3eedb6abb09989784a7dc5e721f9901e936f2c0241967b48858e5e5897b9f24a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4a649ca8da7b5499821a768c650a397216cdc95d826862bf30fcc4725ce8587f"

	strings:
		$s1 = "Win32_Process" fullword ascii
		$s2 = "\\\\%ls\\root\\cimv2" fullword wide
		$op1 = { 83 7b 18 01 75 12 83 63 }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
