rule SIGNATURE_BASE_APT30_Sample_33 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "be6afc4a-97fe-56ba-b057-e21415f9833d"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L919-L939"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "72c568ee2dd75406858c0294ccfcf86ad0e390e4"
		logic_hash = "295c2d9fcf1c3bab54650fd1d203dfb8c12269945aad8927066ef6f815abea69"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Version 4.7.3001" fullword wide
		$s1 = "msmsgr.exe" fullword wide
		$s2 = "MYUSER32.dll" fullword ascii
		$s3 = "MYADVAPI32.dll" fullword ascii
		$s4 = "CeleWare.NET1" fullword ascii
		$s6 = "MYMSVCRT.dll" fullword ascii
		$s7 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the" wide
		$s8 = "WWW.CeleWare.NET1" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and 6 of them
}
