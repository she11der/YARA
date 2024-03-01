rule SIGNATURE_BASE_Ipsearcher : FILE
{
	meta:
		description = "Chinese Hacktool Set - file ipsearcher.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "bb33535a-e8cc-545d-bee8-3c31902eedb9"
		date = "2015-06-13"
		modified = "2022-12-21"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L2343-L2360"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "1e96e9c5c56fcbea94d26ce0b3f1548b224a4791"
		logic_hash = "e63349ede826bc7b0e9c94d122e5b294c11a598fcf7096b80be726146e796a80"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "http://www.wzpg.com" fullword ascii
		$s1 = "ipsearcher\\ipsearcher\\Release\\ipsearcher.pdb" ascii
		$s3 = "_GetAddress" fullword ascii
		$s5 = "ipsearcher.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <140KB and all of them
}
