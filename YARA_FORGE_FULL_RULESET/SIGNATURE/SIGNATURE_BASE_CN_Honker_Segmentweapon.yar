rule SIGNATURE_BASE_CN_Honker_Segmentweapon : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SegmentWeapon.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "e1b6f721-4c4d-50f2-9ed6-f38e8e7ea4ab"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L121-L136"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "494ef20067a7ce2cc95260e4abc16fcfa7177fdf"
		logic_hash = "9afb70a3ae158b7abbda6725b8c9901121b78fa0e874db12b4ac08bf59b26fb5"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" fullword ascii
		$s1 = "http://www.nforange.com/inc/1.asp?" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
