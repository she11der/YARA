rule SIGNATURE_BASE_CN_Honker_Scanhistory : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ScanHistory.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "85585cd2-c5ed-5465-bcac-b61211570055"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2110-L2126"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "14c31e238924ba3abc007dc5a3168b64d7b7de8d"
		logic_hash = "657a25b5103799446fa88abda39d36a05e080c18d41e9dd98199b506f2bfc419"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "ScanHistory.exe" fullword wide
		$s2 = ".\\Report.dat" fullword wide
		$s3 = "select  * from  Results order by scandate desc" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
