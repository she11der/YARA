rule SIGNATURE_BASE_Goodtoolset_Pr : FILE
{
	meta:
		description = "Chinese Hacktool Set - file pr.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "d00e1873-f2a5-5e89-9223-ead418e2667c"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1794-L1812"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f6676daf3292cff59ef15ed109c2d408369e8ac8"
		logic_hash = "0673bc445422f4339c9e81ff8ae8a9b2bb9bc1f107b85fe34906444a1754c43b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "-->This exploit gives you a Local System shell " ascii
		$s3 = "wmiprvse.exe" fullword ascii
		$s4 = "Try the first %d time" fullword ascii
		$s5 = "-->Build&&Change By p " ascii
		$s6 = "root\\MicrosoftIISv2" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
