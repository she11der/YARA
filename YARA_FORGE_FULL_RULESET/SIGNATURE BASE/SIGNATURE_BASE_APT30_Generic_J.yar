rule SIGNATURE_BASE_APT30_Generic_J : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "64a5106e-d7f3-5c68-a14e-410149a1bb9e"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L838-L869"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7c404689b60fe493ca9b503902173ac04d7bb00488edec9e69006e6d51e20c51"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "49aca228674651cba776be727bdb7e60"
		hash2 = "5c7a6b3d1b85fad17333e02608844703"
		hash3 = "649fa64127fef1305ba141dd58fb83a5"
		hash4 = "9982fd829c0048c8f89620691316763a"
		hash5 = "baff5262ae01a9217b10fcd5dad9d1d5"
		hash6 = "9982fd829c0048c8f89620691316763a"

	strings:
		$s0 = "Launcher.EXE" fullword wide
		$s1 = "Symantec Security Technologies" fullword wide
		$s2 = "\\Symantec LiveUpdate.lnk" ascii
		$s3 = "Symantec Service Framework" fullword wide
		$s4 = "\\ccSvcHst.exe" ascii
		$s5 = "\\wssfmgr.exe" ascii
		$s6 = "Symantec Corporation" fullword wide
		$s7 = "\\5.1.0.29" ascii
		$s8 = "\\Engine" ascii
		$s9 = "Copyright (C) 2000-2010 Symantec Corporation. All rights reserved." fullword wide
		$s10 = "Symantec LiveUpdate" fullword ascii
		$s11 = "\\Norton360" ascii
		$s15 = "BinRes" fullword ascii
		$s16 = "\\readme.lz" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
