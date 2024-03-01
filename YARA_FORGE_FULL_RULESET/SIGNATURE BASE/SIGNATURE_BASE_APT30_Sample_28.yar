rule SIGNATURE_BASE_APT30_Sample_28 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "1bc8c68f-ebbb-58b1-92aa-5954318096a0"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L748-L776"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d246a188ad9ec69948bef6018bab1e7a244c76dcf511c3f9d16024ef7e369ae2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e62a63307deead5c9fcca6b9a2d51fb0"
		hash2 = "5b590798da581c894d8a87964763aa8b"

	strings:
		$s0 = "www.flyeagles.com" fullword ascii
		$s1 = "iexplore.exe" fullword ascii
		$s2 = "www.km-nyc.com" fullword ascii
		$s3 = "cmdLine.exe" fullword ascii
		$s4 = "Software\\Microsoft\\CurrentNetInf" fullword ascii
		$s5 = "/dizhi.gif" ascii
		$s6 = "/connect.gif" ascii
		$s7 = "USBTest.sys" fullword ascii
		$s8 = "/ver.htm" fullword ascii
		$s11 = "\\netscv.exe" ascii
		$s12 = "/app.htm" fullword ascii
		$s13 = "\\netsvc.exe" ascii
		$s14 = "/exe.htm" fullword ascii
		$s18 = "MicrosoftHaveAck" fullword ascii
		$s19 = "MicrosoftHaveExit" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and 7 of them
}
