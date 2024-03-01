rule SIGNATURE_BASE_PLUGIN_Trackid : FILE
{
	meta:
		description = "Chinese Hacktool Set - file TracKid.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "8dd77df1-748e-5778-be40-38b794c74b97"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L86-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a114181b334e850d4b33e9be2794f5bb0eb59a09"
		logic_hash = "a62112dbf2ef696e4eb7f6787a0e0930c29d9834f46c87493954498fa4b375f6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "E-mail: cracker_prince@163.com" fullword ascii
		$s1 = ".\\TracKid Log\\%s.txt" fullword ascii
		$s2 = "Coded by prince" fullword ascii
		$s3 = "TracKid.dll" fullword ascii
		$s4 = ".\\TracKid Log" fullword ascii
		$s5 = "%08x -- %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 3 of them
}
