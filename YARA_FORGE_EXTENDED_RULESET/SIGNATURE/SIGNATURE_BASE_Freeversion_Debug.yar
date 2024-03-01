rule SIGNATURE_BASE_Freeversion_Debug : FILE
{
	meta:
		description = "Chinese Hacktool Set - file debug.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "2d69a39a-0da5-56ca-87a5-9116dea6c950"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L692-L711"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d11e6c6f675b3be86e37e50184dadf0081506a89"
		logic_hash = "f7f8302c70c5aed1885724a1bca4efdf0547cc5be62e7dd6bcd8cc2079f71f96"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "c:\\Documents and Settings\\Administrator\\" ascii
		$s1 = "Got WMI process Pid: %d" ascii
		$s2 = "This exploit will execute" ascii
		$s6 = "Found token %s " ascii
		$s7 = "Running reverse shell" ascii
		$s10 = "wmiprvse.exe" fullword ascii
		$s12 = "SELECT * FROM IIsWebInfo" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <820KB and 3 of them
}
