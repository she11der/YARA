rule SIGNATURE_BASE_Kiwitaskmgr_2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file KiwiTaskmgr.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ea021257-8ced-5131-a00a-be014b4112fb"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L2261-L2276"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		logic_hash = "6d197e9b7bb9bbd759d6c8c882f7d7412512ba10208cb52a08fcde5e32fd1733"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Taskmgr no-gpo" fullword wide
		$s3 = "KiwiAndTaskMgr" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
