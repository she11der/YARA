import "pe"

rule SIGNATURE_BASE_Equationgroup_LSADUMP_Lp : FILE
{
	meta:
		description = "EquationGroup Malware - file LSADUMP_Lp.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "8068ca41-6365-5c97-82f2-be9ad89628e0"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1449-L1462"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f67a64ae7fece949d37367d85a28a879e90844e5cc56e88a85a1cce890990f55"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c7bf4c012293e7de56d86f4f5b4eeb6c1c5263568cc4d9863a286a86b5daf194"

	strings:
		$x1 = "LSADUMP - - ERROR - - Injected" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them )
}
