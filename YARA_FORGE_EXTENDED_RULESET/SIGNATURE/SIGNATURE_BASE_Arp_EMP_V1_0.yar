rule SIGNATURE_BASE_Arp_EMP_V1_0 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Arp EMP v1.0.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b2552f26-47ac-5fa0-941e-d674f9deccac"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L918-L931"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ae4954c142ad1552a2abaef5636c7ef68fdd99ee"
		logic_hash = "e46b0f730945dad3c75b6865f30005f4d5fa09c53e3a27c275ca22da9cc89e8d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Arp EMP v1.0.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <800KB and all of them
}
