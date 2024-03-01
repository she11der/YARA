import "pe"

rule SIGNATURE_BASE_Equationgroup_PC_Level3_Http_Flav_Dll : FILE
{
	meta:
		description = "EquationGroup Malware - file PC_Level3_http_flav_dll"
		author = "Florian Roth (Nextron Systems)"
		id = "4bc4804b-c6d2-5c94-b451-24bb0f3dba43"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1430-L1447"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "579539961e29c4da60dc632b1afd348e0d799e266f175a3bae7206b615d90f5b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "27972d636b05a794d17cb3203d537bcf7c379fafd1802792e7fb8e72f130a0c4"

	strings:
		$s1 = "Psxssdll.dll" fullword wide
		$s2 = "Posix Server Dll" fullword wide
		$s4 = "itanium" fullword wide
		$s5 = "RHTTP/1.0" fullword wide
		$s8 = "Copyright (C) Microsoft" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
