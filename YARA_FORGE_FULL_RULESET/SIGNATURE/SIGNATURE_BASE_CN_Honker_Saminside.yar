rule SIGNATURE_BASE_CN_Honker_Saminside : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SAMInside.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c5ac9f0a-d1af-59c3-9c13-91153180f3d8"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1948-L1963"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "707ba507f9a74d591f4f2e2f165ff9192557d6dd"
		logic_hash = "8f095a554121e16b63fdd8d47d957665aed7a2a5885813fa78bc4cee3b8923d3"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "www.InsidePro.com" fullword wide
		$s1 = "SAMInside.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <650KB and all of them
}
