import "pe"

rule SIGNATURE_BASE_Equationgroup_PC_Level3_Http_Flav_Dll_X64 : FILE
{
	meta:
		description = "EquationGroup Malware - file PC_Level3_http_flav_dll_x64"
		author = "Florian Roth (Nextron Systems)"
		id = "93a3d47d-1dac-5621-8e69-d6d23b7628db"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1754-L1771"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b304cb747e609ad5de46624e2d0d005d5f8521e16f0b36cab31535709d7ab72f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4e0209b4f5990148f5d6dee47dbc7021bf78a782b85cef4d6c8be22d698b884f"

	strings:
		$s1 = "Psxssdll.dll" fullword wide
		$s2 = "Posix Server Dll" fullword wide
		$s3 = ".?AVOpenSocket@@" fullword ascii
		$s4 = "RHTTP/1.0" fullword wide
		$s5 = "Copyright (C) Microsoft" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and ( all of ($s*))) or ( all of them )
}
