rule SIGNATURE_BASE_CN_Honker_F4Ck_Team_Blackmoon_Jun15 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file f4ck.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "df12daca-8e03-5382-b71d-96a747d3a043"
		date = "2015-06-23"
		modified = "2023-12-05"
		old_rule_name = "CN_Honker_F4ck_Team_f4ck_3"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2206-L2227"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "7e3bf9b26df08cfa10f10e2283c6f21f5a3a0014"
		logic_hash = "85db31c6bca6e5ddd45168a3adbc382d5a9e8128e0b2a6ed5efe1a2fcd42ff3d"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "File UserName PassWord [comment] /add" fullword ascii
		$s2 = "No Net.exe Add User" fullword ascii
		$s3 = "BlackMoon RunTime Error:" fullword ascii
		$s4 = "Team.F4ck.Net" fullword wide
		$s5 = "admin 123456789" fullword ascii
		$s6 = "blackmoon" fullword ascii
		$s7 = "f4ck Team" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 4 of them
}
