rule SIGNATURE_BASE_CN_Honker_Without_A_Trace_Wywz : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Wywz.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "1093c0c3-499f-5aec-ad4a-878d377296d5"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1538-L1554"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f443c43fde643228ee95def5c8ed3171f16daad8"
		logic_hash = "0f6ca7d44312afef49d3094af7b33af5e41f4531e7e7f9f37cf050700755bb3e"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\Symantec\\Norton Personal Firewall\\Log\\Content.log" ascii
		$s2 = "UpdateFile=d:\\tool\\config.ini,Option\\\\proxyIp=127.0.0.1\\r\\nproxyPort=808" ascii
		$s3 = "%s\\subinacl.exe /subkeyreg \"%s\" /Grant=%s=f /Grant=everyone=f" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1800KB and all of them
}
