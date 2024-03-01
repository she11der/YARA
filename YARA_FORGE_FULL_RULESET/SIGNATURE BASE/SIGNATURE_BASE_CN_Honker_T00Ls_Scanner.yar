rule SIGNATURE_BASE_CN_Honker_T00Ls_Scanner : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls_scanner.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "80d4a950-24cb-55c7-903f-8788a71be7ac"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1263-L1278"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "70b04b910d82b32b90cd7f355a0e3e17dd260cb3"
		logic_hash = "558abb651ce410520811ca96aaad78710cb9bf597b59ed89d9a678377716d721"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "http://cn.bing.com/search?first=1&count=50&q=ip:" fullword wide
		$s17 = "Team:www.t00ls.net" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <330KB and all of them
}
