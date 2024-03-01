rule SIGNATURE_BASE_Fourelementsword_Elevatedll : FILE
{
	meta:
		description = "Detects FourElementSword Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "06879d75-18a3-5d49-a963-fa4bee379387"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_four_element_sword.yar#L158-L179"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d110bae02f00d14c5a71ecf5991e9fc38b29d8056d1e551dc36376875d2e1333"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "3dfc94605daf51ebd7bbccbb3a9049999f8d555db0999a6a7e6265a7e458cab9"
		hash2 = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"

	strings:
		$x1 = "Elevate.dll" fullword wide
		$x2 = "ResN32.dll" fullword wide
		$s1 = "Kingsoft\\Antivirus" fullword wide
		$s2 = "KasperskyLab\\protected" fullword wide
		$s3 = "Sophos" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 1 of ($x*) and all of ($s*)) or ( all of them )
}
