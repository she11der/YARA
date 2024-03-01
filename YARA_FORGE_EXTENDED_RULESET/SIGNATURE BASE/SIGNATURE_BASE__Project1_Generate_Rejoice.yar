rule SIGNATURE_BASE__Project1_Generate_Rejoice : FILE
{
	meta:
		description = "Chinese Hacktool Set - from files Project1.exe, Generate.exe, rejoice.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4b36d450-1194-527c-8565-7f321d486d01"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L2476-L2497"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b66bb4d392881468b33a8ee4458f33bfe7a82d34cc3927eedccd54ad94ff6a04"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
		hash1 = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
		hash2 = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"

	strings:
		$s1 = "sfUserAppDataRoaming" fullword ascii
		$s2 = "$TRzFrameControllerPropertyConnection" fullword ascii
		$s3 = "delphi32.exe" fullword ascii
		$s4 = "hkeyCurrentUser" fullword ascii
		$s5 = "%s is not a valid IP address." fullword wide
		$s6 = "Citadel hooking error" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
