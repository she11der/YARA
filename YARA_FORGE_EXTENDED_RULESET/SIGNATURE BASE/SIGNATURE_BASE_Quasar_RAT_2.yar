rule SIGNATURE_BASE_Quasar_RAT_2 : FILE
{
	meta:
		description = "Detects Quasar RAT"
		author = "Florian Roth (Nextron Systems)"
		id = "0ca795c5-3631-5a99-8675-37558485f478"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_quasar_rat.yar#L35-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b113cb63b0bb75766c905dd3b327b1b2df228733622df8f7517d3daed72432a3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "0774d25e33ca2b1e2ee2fafe3fdbebecefbf1d4dd99e6460f0bc8713dd0fd740"
		hash2 = "515c1a68995557035af11d818192f7866ef6a2018aa13112fefbe08395732e89"
		hash3 = "f08db220df716de3d4f63f3007a03f902601b9b32099d6a882da87312f263f34"

	strings:
		$x1 = "GetKeyloggerLogsResponse" fullword ascii
		$x2 = "get_Keylogger" fullword ascii
		$x3 = "HandleGetKeyloggerLogsResponse" fullword ascii
		$s1 = "DoShellExecuteResponse" fullword ascii
		$s2 = "GetPasswordsResponse" fullword ascii
		$s3 = "GetStartupItemsResponse" fullword ascii
		$s4 = "<GetGenReader>b__7" fullword ascii
		$s5 = "RunHidden" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <5000KB and $x1) or ( all of them )
}
