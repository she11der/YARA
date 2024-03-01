import "pe"

rule SIGNATURE_BASE_Equationgroup_Equationdrug_Tdi6 : FILE
{
	meta:
		description = "EquationGroup Malware - file tdi6.sys"
		author = "Florian Roth (Nextron Systems)"
		id = "c6dbc28a-ec52-5256-afff-ab15ed1b90a6"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1626-L1642"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ba7e14a3bf158795ecee498976847fbbcc80635799be4574f05aa80d1a85a4ef"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "12c082f74c0916a0e926488642236de3a12072a18d29c97bead15bb301f4b3f8"

	strings:
		$s1 = "tdi6.sys" fullword wide
		$s3 = "TDI IPv6 Wrapper" fullword wide
		$s5 = "Corporation. All rights reserved." fullword wide
		$s6 = "FailAction" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
