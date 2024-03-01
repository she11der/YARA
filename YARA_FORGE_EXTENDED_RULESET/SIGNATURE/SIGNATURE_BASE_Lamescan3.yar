rule SIGNATURE_BASE_Lamescan3 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file lamescan3.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8ff1a0e6-d054-589d-a038-f889951ba250"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1161-L1177"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3130eefb79650dab2e323328b905e4d5d3a1d2f0"
		logic_hash = "8246128fa4378b0479a0c051965188c7c3fa0f52c8acc8934ef8af3155a85590"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "dic\\loginlist.txt" fullword ascii
		$s2 = "Radmin.exe" fullword ascii
		$s3 = "lamescan3.pdf!" fullword ascii
		$s4 = "dic\\passlist.txt" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3740KB and all of them
}
