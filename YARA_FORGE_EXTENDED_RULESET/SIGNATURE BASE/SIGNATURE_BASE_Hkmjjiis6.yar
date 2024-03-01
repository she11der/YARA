rule SIGNATURE_BASE_Hkmjjiis6 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file hkmjjiis6.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "9618c6ec-1557-5b1b-bebc-1c220bb3aba4"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1337-L1358"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4cbc6344c6712fa819683a4bd7b53f78ea4047d7"
		logic_hash = "4ea95b7a5bd24e0dfdcef045d101b7f15e18b20f1328901bb340d9aaad336981"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "comspec" fullword ascii
		$s2 = "user32.dlly" ascii
		$s3 = "runtime error" ascii
		$s4 = "WinSta0\\Defau" ascii
		$s5 = "AppIDFlags" fullword ascii
		$s6 = "GetLag" fullword ascii
		$s7 = "* FROM IIsWebInfo" ascii
		$s8 = "wmiprvse.exe" ascii
		$s9 = "LookupAcc" ascii

	condition:
		uint16(0)==0x5a4d and filesize <70KB and all of them
}
