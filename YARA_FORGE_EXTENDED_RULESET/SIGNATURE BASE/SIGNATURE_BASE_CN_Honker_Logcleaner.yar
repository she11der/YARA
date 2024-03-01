rule SIGNATURE_BASE_CN_Honker_Logcleaner : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LogCleaner.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "63ec5e47-9f3e-547a-bbff-cac8b27ac8f7"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L845-L860"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ab77ed5804b0394d58717c5f844d9c0da5a9f03e"
		logic_hash = "3be059627c39e262e7621fce637df21ddcabef91753192cec356f2f8cd58c1a3"
		score = 70
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = ".exe <ip> [(path]" fullword ascii
		$s4 = "LogCleaner v" ascii

	condition:
		uint16(0)==0x5a4d and filesize <250KB and all of them
}
