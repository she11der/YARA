import "pe"

rule SIGNATURE_BASE_Equationgroup_Processhide_Lp : FILE
{
	meta:
		description = "EquationGroup Malware - file ProcessHide_Lp.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "b0842897-f591-5213-9a26-0f8732e6f3b8"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1374-L1393"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "407045f5ac8eeec4403560de406e5d382d38ae2f34d0e4c7d3cc9b94debdfad8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "cdee0daa816f179e74c90c850abd427fbfe0888dcfbc38bf21173f543cdcdc66"

	strings:
		$x1 = "Invalid flag.  Can only hide or unhide" fullword wide
		$x2 = "Process elevation failed" fullword wide
		$x3 = "Unknown error hiding process" fullword wide
		$x4 = "Invalid process links found in EPROCESS" fullword wide
		$x5 = "Unable to find SYSTEM process" fullword wide
		$x6 = "Process hidden, but EPROCESS location lost" fullword wide
		$x7 = "Invalid EPROCESS location for given ID" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them ) or (3 of them )
}
