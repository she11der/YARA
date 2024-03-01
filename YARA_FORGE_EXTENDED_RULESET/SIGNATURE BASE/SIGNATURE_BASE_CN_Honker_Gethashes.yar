rule SIGNATURE_BASE_CN_Honker_Gethashes : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetHashes.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b1c5910d-0fb1-547e-92b7-5fcf183e38a6"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1280-L1296"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "dc8bcebf565ffffda0df24a77e28af681227b7fe"
		logic_hash = "fb5ab5e6d8b522caf27478b0589b39d06b96fb0f913673ede768a814836e11f8"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "SAM\\Domains\\Account\\Users\\Names registry hive reading error!" fullword ascii
		$s1 = "GetHashes <SAM registry file> [System key file]" fullword ascii
		$s2 = "Note: Windows registry file shall begin from 'regf' signature!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <87KB and 2 of them
}
