rule SIGNATURE_BASE_CN_Honker_Shell_Brute_Tool : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file shell_brute_tool.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "80fd0c9f-0ed9-5308-ac72-65b9b3b47ed1"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L862-L877"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f6903a15453698c35dce841e4d09c542f9480f01"
		logic_hash = "723fd18e59c0017b67a035ec7c685169c517d673c2bbc8fe93071b8dbd1e606a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "http://24hack.com/xyadmin.asp" fullword ascii
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
