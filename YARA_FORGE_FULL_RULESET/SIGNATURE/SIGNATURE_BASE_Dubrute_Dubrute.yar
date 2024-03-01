rule SIGNATURE_BASE_Dubrute_Dubrute : FILE
{
	meta:
		description = "Chinese Hacktool Set - file DUBrute.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "10aa2017-d563-5953-8672-dbc13ff6b3cf"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L259-L275"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8aaae91791bf782c92b97c6e1b0f78fb2a9f3e65"
		logic_hash = "1e6d8bd24a37e3f4b7de88989251ae904128ff1bf766d4a4408ff8990c6dfd2f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
		$s2 = "IP - 0; Login - 0; Password - 0; Combination - 0" fullword ascii
		$s3 = "Create %d IP@Loginl;Password" fullword ascii
		$s4 = "UBrute.com" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1020KB and all of them
}
