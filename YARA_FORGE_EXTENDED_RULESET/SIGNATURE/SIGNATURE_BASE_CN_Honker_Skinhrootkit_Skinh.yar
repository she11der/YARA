rule SIGNATURE_BASE_CN_Honker_Skinhrootkit_Skinh : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SkinH.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8aedd01c-9dc8-537d-97ea-bc8de81edd3d"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2340-L2356"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d593f03ae06e54b653c7850c872c0eed459b301f"
		logic_hash = "97314a8c908c714c39ea8962c87709fdc422c3e2998a2b1694950fa127204335"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "(C)360.cn Inc.All Rights Reserved." fullword wide
		$s1 = "SDVersion.dll" fullword wide
		$s2 = "skinh.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
