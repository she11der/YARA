rule SIGNATURE_BASE_APT30_Sample_11 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L285-L312"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "59066d5d1ee3ad918111ed6fcaf8513537ff49a6"
		logic_hash = "5e86b53591caa7c783a946205a3d04f91c71294d844e6f6ee88c3bc78e603ea0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "System\\CurrentControlSet\\control\\ComputerName\\ComputerName" fullword ascii
		$s1 = "msofscan.exe" fullword wide
		$s2 = "Mozilla/4.0 (compatible; MSIE 5.0; Win32)" fullword ascii
		$s3 = "Microsoft? is a registered trademark of Microsoft Corporation." fullword wide
		$s4 = "Windows XP Professional x64 Edition or Windows Server 2003" fullword ascii
		$s9 = "NetEagle_Scout - " fullword ascii
		$s10 = "Server 4.0, Enterprise Edition" fullword ascii
		$s11 = "Windows 3.1(Win32s)" fullword ascii
		$s12 = "%s%s%s %s" fullword ascii
		$s13 = "Server 4.0" fullword ascii
		$s15 = "Windows Millennium Edition" fullword ascii
		$s16 = "msofscan" fullword wide
		$s17 = "Eagle-Norton360-OfficeScan" fullword ascii
		$s18 = "Workstation 4.0" fullword ascii
		$s19 = "2003 Microsoft Office system" fullword wide

	condition:
		filesize <250KB and uint16(0)==0x5A4D and all of them
}
