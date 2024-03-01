rule SIGNATURE_BASE_CN_Honker_Injection : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Injection.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8600c86f-0da1-5ddb-bae5-69358cf53e7c"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1756-L1771"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3484ed16e6f9e0d603cbc5cb44e46b8b7e775d35"
		logic_hash = "8de3e59bd118fbbf1a012c6bfb358dba7c8fb758e3ac17277f2ad3a92c0284ba"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "http://127.0.0.1/6kbbs/bank.asp" fullword ascii
		$s7 = "jmPost.asp" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <220KB and all of them
}
