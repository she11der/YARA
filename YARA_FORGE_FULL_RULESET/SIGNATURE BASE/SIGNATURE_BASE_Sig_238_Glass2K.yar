import "pe"

rule SIGNATURE_BASE_Sig_238_Glass2K
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Glass2k.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7a2ad37a-6b55-5710-b07d-7c289cdbb04e"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2459-L2476"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b05455a1ecc6bc7fc8ddef312a670f2013704f1a"
		logic_hash = "d9b6b904028d67804d095f85caea5796f528f866191d3b4250055a75511f2090"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Portions Copyright (c) 1997-1999 Lee Hasiuk" fullword ascii
		$s1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98" fullword ascii
		$s3 = "WINNT\\System32\\stdole2.tlb" fullword ascii
		$s4 = "Glass2k.exe" fullword wide
		$s7 = "NeoLite Executable File Compressor" fullword ascii

	condition:
		all of them
}
