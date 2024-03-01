rule SIGNATURE_BASE_CN_Honker_Master_Beta_1_7 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Master_beta_1.7.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "78f904ec-f7cb-5fd0-a117-925ebedd1d3e"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1411-L1426"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3be7a370791f29be89acccf3f2608fd165e8059e"
		logic_hash = "13c9cc0bf8aaed2ba86baeee6f0b32bf71108dc1350dcffd03e70393fa975c9f"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "http://seo.chinaz.com/?host=" fullword ascii
		$s2 = "Location: getpass.asp?info=" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <312KB and all of them
}
