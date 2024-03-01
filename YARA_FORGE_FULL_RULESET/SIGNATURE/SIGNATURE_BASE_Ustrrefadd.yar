rule SIGNATURE_BASE_Ustrrefadd : FILE
{
	meta:
		description = "Chinese Hacktool Set - file ustrrefadd.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "e6701e7e-bb15-5e0c-822b-3e29342e083c"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L367-L384"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b371b122460951e74094f3db3016264c9c8a0cfa"
		logic_hash = "e44f180e081494e28b35b4129eb2c1817ed3e83f23d86f0d3dd4dcf27941cdf1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "E-Mail  : admin@luocong.com" fullword ascii
		$s1 = "Homepage: http://www.luocong.com" fullword ascii
		$s2 = ": %d  -  " fullword ascii
		$s3 = "ustrreffix.dll" fullword ascii
		$s5 = "Ultra String Reference plugin v%d.%02d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <320KB and all of them
}
