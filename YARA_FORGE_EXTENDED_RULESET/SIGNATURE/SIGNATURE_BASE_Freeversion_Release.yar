rule SIGNATURE_BASE_Freeversion_Release : FILE
{
	meta:
		description = "Chinese Hacktool Set - file release.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "1a603634-a00a-5f8b-a47d-c3c8065a5c3e"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1644-L1662"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f42e4b5748e92f7a450eb49fc89d6859f4afcebb"
		logic_hash = "38722afb3b955aced2e68e2048a3268722524f61784dcb45c6a695b5684230eb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "This exploit will execute \"net user " ascii
		$s3 = "net user temp 123456 /add & net localgroup administrators temp /add" fullword ascii
		$s4 = "Running reverse shell" ascii
		$s5 = "wmiprvse.exe" fullword ascii
		$s6 = "SELECT * FROM IIsWebInfo" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 3 of them
}
