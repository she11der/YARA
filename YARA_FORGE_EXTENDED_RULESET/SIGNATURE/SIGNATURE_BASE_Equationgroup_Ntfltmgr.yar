import "pe"

rule SIGNATURE_BASE_Equationgroup_Ntfltmgr : FILE
{
	meta:
		description = "EquationGroup Malware - file ntfltmgr.sys"
		author = "Florian Roth (Nextron Systems)"
		id = "dd7fd371-a097-5df5-9ffd-89babbadee96"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1663-L1679"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "3e931088f363c7dfb6057019faf9e5c674c90f6bdae6211dcc871464b410efd3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f7a886ee10ee6f9c6be48c20f370514be62a3fd2da828b0dff44ff3d485ff5c5"

	strings:
		$s1 = "ntfltmgr.sys" fullword wide
		$s2 = "ntfltmgr.pdb" fullword ascii
		$s4 = "Network Filter Manager" fullword wide
		$s5 = "Corporation. All rights reserved." fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
