rule SIGNATURE_BASE_CN_Honker_F4Ck_Team_F4Ck_2 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file f4ck_2.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b2a9067f-57d0-5b32-87c8-3b635c3944a5"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1428-L1446"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0783661077312753802bd64bf5d35c4666ad0a82"
		logic_hash = "85c73d480019929eef5951b0395f49cea86dc83b334860e940cc6e36c2d96d3a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "F4ck.exe" fullword wide
		$s2 = "@Netapi32.dll" fullword ascii
		$s3 = "Team.F4ck.Net" fullword wide
		$s8 = "Administrators" fullword ascii
		$s9 = "F4ck Team" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <220KB and 2 of them
}
