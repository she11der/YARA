rule SIGNATURE_BASE_Derusbi_Backdoor_Mar17_1 : FILE
{
	meta:
		description = "Detects a variant of the Derusbi backdoor"
		author = "Florian Roth (Nextron Systems)"
		id = "5c8838d6-b9c2-589e-b6a2-a8c7ad6f10cc"
		date = "2017-03-03"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_derusbi.yar#L123-L143"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "068a8d5c7378c6cf9d0369374550cd34b54e9f913aa7512a6beb46395fc15b19"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f87915f21dcc527981ebb6db3d332b5b341129b4af83524f59d7178e9d2a3a32"

	strings:
		$x1 = "%SystemRoot%\\System32\\wiaservc.dll" fullword wide
		$x2 = "c%WINDIR%\\PCHealth\\HelpCtr\\Binaries\\pchsvc.dll" fullword wide
		$x3 = "%Systemroot%\\Help\\perfc009.dat" fullword wide
		$x4 = "rundll32.exe \"%s\", R32 %s" fullword wide
		$x5 = "OfficeUt32.dll" fullword ascii
		$x6 = "\\\\.\\pipe\\usb%so" fullword wide
		$x7 = "\\\\.\\pipe\\usb%si" fullword wide
		$x8 = "\\tmp1.dat" wide

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 1 of them )
}
