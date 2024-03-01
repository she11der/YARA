rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Shares_Target : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "51245be4-6d24-57e4-8c92-c8c1ae5e3cf9"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2433-L2449"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "11a1af97d720286a7fadf8b056f8f7add70acb041a828441166f5c74bc7a819d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6c57fb33c5e7d2dee415ae6168c9c3e0decca41ffe023ff13056ff37609235cb"

	strings:
		$s1 = "Select * from Win32_Share" fullword ascii
		$s2 = "slocalhost" fullword wide
		$s3 = "\\\\%ls\\root\\cimv2" fullword wide
		$s4 = "\\\\%ls\\%ls" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
