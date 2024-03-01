rule SIGNATURE_BASE_CN_Honker_Cleaner_Cl_2 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file cl.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "9aa36c0a-9e0f-5274-bebe-9179d81b05f7"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1913-L1928"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "523084e8975b16e255b56db9af0f9eecf174a2dd"
		logic_hash = "865354152f8441009aaad9022f64c3a014c4df0549b648d66959df56893ab98a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "cl -eventlog All/Application/System/Security" fullword ascii
		$s1 = "clear iislog error!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <50KB and all of them
}
