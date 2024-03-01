rule SIGNATURE_BASE_Sql1433_Creck : FILE
{
	meta:
		description = "Chinese Hacktool Set - file creck.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "38a91464-d493-5154-86ec-e54b3e25309b"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktool_scripts.yar#L110-L125"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "189c11a3b268789a3fbcfac3bd4e03cbfde87b1d"
		logic_hash = "2d9ff5f130d625450e7de41832695839f0427a6186569280a224f20e89fe1d8a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "start anhao3.exe -i S.txt -p  pass3.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii
		$s1 = "start anhao1.exe -i S.txt -p  pass1.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii
		$s2 = "start anhao2.exe -i S.txt -p  pass2.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii

	condition:
		uint16(0)==0x7473 and filesize <1KB and 1 of them
}
