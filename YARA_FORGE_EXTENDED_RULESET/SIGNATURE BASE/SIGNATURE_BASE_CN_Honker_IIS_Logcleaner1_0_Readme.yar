rule SIGNATURE_BASE_CN_Honker_IIS_Logcleaner1_0_Readme : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file readme.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "6f3605ab-cf9d-5f6b-8d89-6269976c5b0b"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_scripts.yar#L274-L289"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "2ab47d876b49e9a693f602f3545381415e82a556"
		logic_hash = "3cbd7b2e1710c78bc8ab8d2730cc6da8eb95038f8431d5d0081db984b3d706cf"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "LogCleaner.exe <ip> [Logpath]" fullword ascii
		$s3 = "http://l-y.vicp.net" fullword ascii

	condition:
		filesize <7KB and all of them
}
