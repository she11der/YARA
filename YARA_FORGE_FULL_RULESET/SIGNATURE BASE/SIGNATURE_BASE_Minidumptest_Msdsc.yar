rule SIGNATURE_BASE_Minidumptest_Msdsc : FILE
{
	meta:
		description = "Auto-generated rule - file msdsc.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "044ae157-aba2-5935-9afc-8a12853c84bc"
		date = "2015-08-31"
		modified = "2023-12-05"
		reference = "https://github.com/giMini/RWMC/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_rwmc_powershell_creddump.yar#L26-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "477034933918c433f521ba63d2df6a27cc40a5833a78497c11fb0994d2fd46ba"
		logic_hash = "ae8a28df245a8f7a2d62639789c31556b012322fcac09784595fd6f95d6bf195"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "MiniDumpTest1.exe" fullword wide
		$s2 = "MiniDumpWithTokenInformation" fullword ascii
		$s3 = "MiniDumpTest1" fullword wide
		$s6 = "Microsoft 2008" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and all of them
}
