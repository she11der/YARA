rule SIGNATURE_BASE_APT30_Sample_13 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L331-L349"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a359f705a833c4a4254443b87645fd579aa94bcf"
		logic_hash = "cd5285e8b78493b64704cec21c13d0a017d66936aa8356cfea2aa77c6f87b9e7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "msofscan.exe" fullword wide
		$s1 = "Microsoft? is a registered trademark of Microsoft Corporation." fullword wide
		$s2 = "Microsoft Office Word Plugin Scan" fullword wide
		$s3 = "? 2006 Microsoft Corporation.  All rights reserved." fullword wide
		$s4 = "msofscan" fullword wide
		$s6 = "2003 Microsoft Office system" fullword wide

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
