import "pe"

rule SIGNATURE_BASE_Equationgroup_Equationdrug_Gen_5 : FILE
{
	meta:
		description = "EquationGroup Malware - file PC_Level3_http_dll"
		author = "Florian Roth (Nextron Systems)"
		id = "a67655eb-5593-5ac7-a6aa-81f235fa3c33"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1412-L1428"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "834a7175a23c30301fce01482a2768d453368c7ca5c72ae52b2d266b31005991"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4ebfc1f6ec6a0e68e47e5b231331470a4483184cf715a578191b91ba7c32094d"

	strings:
		$s1 = "Psxssdll.dll" fullword wide
		$s2 = "Posix Server Dll" fullword wide
		$s3 = "itanium" fullword wide
		$s6 = "Copyright (C) Microsoft" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
