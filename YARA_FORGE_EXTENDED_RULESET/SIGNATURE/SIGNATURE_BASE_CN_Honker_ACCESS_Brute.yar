rule SIGNATURE_BASE_CN_Honker_ACCESS_Brute : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ACCESS_brute.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7ceaea93-4f23-50a3-ab39-8149b10ffdad"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2250-L2268"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f552e05facbeb21cb12f23c34bb1881c43e24c34"
		logic_hash = "5bd0cbb1c2f5863ef1365dc115c736ade05c290cd6fa09a24c2d344314b522cb"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = ".dns166.co" ascii
		$s2 = "SExecuteA" ascii
		$s3 = "ality/clsCom" ascii
		$s4 = "NT_SINK_AddRef" ascii
		$s5 = "WINDOWS\\Syswm" ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and all of them
}
