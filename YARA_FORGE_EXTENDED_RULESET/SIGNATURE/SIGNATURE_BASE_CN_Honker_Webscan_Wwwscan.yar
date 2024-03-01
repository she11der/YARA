rule SIGNATURE_BASE_CN_Honker_Webscan_Wwwscan : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file wwwscan.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "defe0024-f94a-560a-a9f6-b3849b41f9bb"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1965-L1981"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "6dbffa916d0f0be2d34c8415592b9aba690634c7"
		logic_hash = "9d2eee1c1783a08a2eae86d4ea77bdb67db8cf0055a24d88ea09411e63018e8c"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii
		$s2 = "GET /nothisexistpage.html HTTP/1.1" fullword ascii
		$s3 = "<Usage>:  %s <HostName|Ip> [Options]" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and all of them
}
