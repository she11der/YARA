rule SIGNATURE_BASE_Dos_Look : FILE
{
	meta:
		description = "Chinese Hacktool Set - file look.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "910d1469-9173-5a7d-91ea-a50ee921f662"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L713-L728"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e1a37f31170e812185cf00a838835ee59b8f64ba"
		logic_hash = "341c72eaa5db1953e008423374c3f322de0f8dc33fd8181362172982b52e2b8a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<description>CHKen QQ:41901298</description>" fullword ascii
		$s2 = "version=\"9.9.9.9\"" fullword ascii
		$s3 = "name=\"CH.Ken.Tool\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and all of them
}
