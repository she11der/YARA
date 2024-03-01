rule SIGNATURE_BASE_Radmin_Hash : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Radmin_Hash.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "07761e81-15b4-5639-b766-8dc3f16e2b7a"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1588-L1605"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "be407bd5bf5bcd51d38d1308e17a1731cd52f66b"
		logic_hash = "d6ee13a2ed30bb44471593386521f67be0d6ccd6f8a0ebf8557012a099f81d3d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<description>IEBars</description>" fullword ascii
		$s2 = "PECompact2" fullword ascii
		$s3 = "Radmin, Remote Administrator" fullword wide
		$s4 = "Radmin 3.0 Hash " fullword wide
		$s5 = "HASH1.0" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <600KB and all of them
}
