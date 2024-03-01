rule SIGNATURE_BASE_Kelloworld_2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file kelloworld.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "3f298004-e618-5f4a-9cd7-c7c954b6fc64"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L2440-L2455"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		logic_hash = "a575c30c06bd84196cbf01a9b5ef3a042cf29553610421b019227d30a2c7ad1c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Hello World!" fullword wide
		$s2 = "kelloworld.dll" fullword ascii
		$s3 = "kelloworld de mimikatz pour Windows" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
