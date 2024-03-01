rule SIGNATURE_BASE_Webcrack4_Routerpasswordcracking : FILE
{
	meta:
		description = "Chinese Hacktool Set - file WebCrack4-RouterPasswordCracking.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "e3d50ff8-e58d-5c60-9acd-25ba95a21f68"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L749-L766"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "00c68d1b1aa655dfd5bb693c13cdda9dbd34c638"
		logic_hash = "48456f82163806852ecef3d71c2c8247f6c74c31ce28472c80a914a98247bdb3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "http://www.site.com/test.dll?user=%USERNAME&pass=%PASSWORD" fullword ascii
		$s1 = "Username: \"%s\", Password: \"%s\", Remarks: \"%s\"" fullword ascii
		$s14 = "user:\"%s\" pass: \"%s\" result=\"%s\"" fullword ascii
		$s16 = "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)" fullword ascii
		$s20 = "List count out of bounds (%d)+Operation not allowed on sorted string list%String" wide

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and 2 of them
}
