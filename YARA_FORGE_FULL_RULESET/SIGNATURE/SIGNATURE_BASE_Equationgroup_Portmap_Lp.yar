import "pe"

rule SIGNATURE_BASE_Equationgroup_Portmap_Lp : FILE
{
	meta:
		description = "EquationGroup Malware - file PortMap_Lp.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "e1851a17-9858-5c93-9993-2da0559e5d2e"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1853-L1868"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9666e64b40dc01c5b3756b1334519730765f7075ba9a124a79f5b7ea4bc91e03"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2b27f2faae9de6330f17f60a1d19f9831336f57fdfef06c3b8876498882624a6"

	strings:
		$s1 = "Privilege elevation failed" fullword wide
		$s2 = "Portmap ended due to max number of ports" fullword wide
		$s3 = "Invalid parameters received for portmap" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 2 of them )
}
