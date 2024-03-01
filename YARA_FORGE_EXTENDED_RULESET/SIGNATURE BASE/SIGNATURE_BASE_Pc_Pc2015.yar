rule SIGNATURE_BASE_Pc_Pc2015 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file pc2015.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "aa7c0b5e-91c3-52cc-9e06-b4648d0b8825"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L106-L121"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "de4f098611ac9eece91b079050b2d0b23afe0bcb"
		logic_hash = "34d66d8b9e637c067ec2d9387b7b57458312d75892e33b95eb1095200799cf3b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\svchost.exe" ascii
		$s1 = "LON\\OD\\O-\\O)\\O%\\O!\\O=\\O9\\O5\\O1\\O" fullword ascii
		$s8 = "%s%08x.001" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <309KB and all of them
}
