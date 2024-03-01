rule SIGNATURE_BASE_CN_Honker_Injection_Transit : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Injection_transit.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8600c86f-0da1-5ddb-bae5-69358cf53e7c"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1626-L1642"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f4fef2e3d310494a3c3962a49c7c5a9ea072b2ea"
		logic_hash = "3e6fe804b9b6e8555c847a165bb0a8b266004653531fe8f11e3937108757f2ff"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<description>Your app description here</description> " fullword ascii
		$s4 = "Copyright (C) 2003 ZYDSoft Corp." fullword wide
		$s5 = "ScriptnackgBun" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3175KB and all of them
}
