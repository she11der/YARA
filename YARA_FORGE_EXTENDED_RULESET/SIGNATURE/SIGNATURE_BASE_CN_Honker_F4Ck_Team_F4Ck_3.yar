rule SIGNATURE_BASE_CN_Honker_F4Ck_Team_F4Ck_3 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file F4ck_3.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "1767669f-47d0-5d6e-97a5-92522f988102"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2229-L2248"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0b3e9381930f02e170e484f12233bbeb556f3731"
		logic_hash = "870d22be85da127b3ebfd3f8ec547b6ad1cdc8048b56aea494e8d2643bd61d77"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "F4ck.exe" fullword wide
		$s2 = "@Netapi32.dll" fullword ascii
		$s3 = "Team.F4ck.Net" fullword wide
		$s6 = "NO Net Add User" fullword wide
		$s7 = "DLL ERROR" fullword ascii
		$s11 = "F4ck Team" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 3 of them
}
