import "pe"

rule SIGNATURE_BASE_Equationgroup_Equationdrug_Ntevt : FILE
{
	meta:
		description = "EquationGroup Malware - file ntevt.sys"
		author = "Florian Roth (Nextron Systems)"
		id = "36d23adb-dafe-5e99-8976-b146ceca2f9b"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1577-L1591"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c5259c89dfedc34ca032775bda4ead04985da6b3d042b8a6635f5f848570d8c6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "45e5e1ea3456d7852f5c610c7f4447776b9f15b56df7e3a53d57996123e0cebf"

	strings:
		$s1 = "ntevt.sys" fullword ascii
		$s2 = "c:\\ntevt.pdb" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and all of them )
}
