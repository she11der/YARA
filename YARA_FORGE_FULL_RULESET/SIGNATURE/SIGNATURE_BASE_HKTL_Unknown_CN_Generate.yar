rule SIGNATURE_BASE_HKTL_Unknown_CN_Generate : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Generate.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "88ad2c71-519f-58b0-87f8-a6f54a54a774"
		date = "2015-06-13"
		modified = "2022-01-20"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2029-L2047"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
		logic_hash = "a83000880bd71f4ee6507cb448b611cb670a47a4dc47c400930d3a41ca594a5d"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "C:\\TEMP\\" ascii
		$s2 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s3 = "$530 Please login with USER and PASS." fullword ascii
		$s4 = "_Shell.exe" fullword ascii
		$s5 = "ftpcWaitingPassword" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 3 of them
}
