import "pe"

rule SIGNATURE_BASE_Equationgroup_Equationdrug_Gen_6 : FILE
{
	meta:
		description = "EquationGroup Malware - file PC_Level3_dll_x64"
		author = "Florian Roth (Nextron Systems)"
		id = "99b2fab0-1298-5d48-a78b-eb59942ecfca"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1737-L1752"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5a14bd8efe2cf68beec207e5deec28fd5b9d89c506593214eccbceae3cb862a7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "339855618fb3ef53987b8c14a61bd4519b2616e766149e0c21cbd7cbe7a632c9"

	strings:
		$s1 = "Psxssdll.dll" fullword wide
		$s2 = "Posix Server Dll" fullword wide
		$s3 = "Copyright (C) Microsoft" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
