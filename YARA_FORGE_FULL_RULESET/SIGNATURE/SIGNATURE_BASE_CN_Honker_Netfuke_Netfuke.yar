rule SIGNATURE_BASE_CN_Honker_Netfuke_Netfuke : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file NetFuke.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "833da5c7-e562-50e9-a2a9-54c36b0d1f61"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L703-L718"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f89e223fd4f6f5a3c2a2ea225660ef0957fc07ba"
		logic_hash = "86f6040b743b17fb300498b02a202d1a9090054a30d490f082b116d799c4bdb2"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Mac Flood: Flooding %dT %d p/s " fullword ascii
		$s2 = "netfuke_%s.txt" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1840KB and all of them
}
