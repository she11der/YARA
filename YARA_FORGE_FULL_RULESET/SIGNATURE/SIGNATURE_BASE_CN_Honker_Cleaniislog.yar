rule SIGNATURE_BASE_CN_Honker_Cleaniislog : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CleanIISLog.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3931ba63-faf5-5b44-879c-105cd2812712"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1880-L1894"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "827cd898bfe8aa7e9aaefbe949d26298f9e24094"
		logic_hash = "35b428d6178196b0dc6ac2ea3f0ee1dfbf6a98ead2356cb2a35d3d6b780538cc"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Usage: CleanIISLog <LogFile>|<.> <CleanIP>|<.>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
