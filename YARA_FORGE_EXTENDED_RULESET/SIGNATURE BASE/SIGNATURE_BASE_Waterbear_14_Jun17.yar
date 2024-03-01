rule SIGNATURE_BASE_Waterbear_14_Jun17 : FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "515d9400-3e2e-5ee5-a7dd-b313125c6482"
		date = "2017-06-23"
		modified = "2023-12-05"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_waterbear.yar#L245-L261"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9ebe46590556e8eba2eef1c007549f6141c917bab97d46a0d58eca56257e24e2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "00a1068645dbe982a9aa95e7b8202a588989cd37de2fa1b344abbc0102c27d05"
		hash2 = "53330a80b3c4f74f3f10a8621dbef4cd2427723e8b98c5b7aed58229d0c292ba"
		hash3 = "bdcb23a82ac4eb1bc9254d77d92b6f294d45501aaea678a3d21c8b188e31e68b"

	strings:
		$s1 = "my.com/msg/util/sgthash" fullword ascii
		$s2 = "C:\\recycled" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <8000KB and all of them )
}
