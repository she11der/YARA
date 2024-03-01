rule SIGNATURE_BASE_APT30_Sample_29 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "24334885-fcb4-5a13-82e8-c8465f97361e"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L778-L798"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "44492c53715d7c79895904543843a321491cb23a"
		logic_hash = "7a59118ba00413961e6fc4d54680373d033a38d698613f853f67137b85c123a7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "LSSAS.exe" fullword ascii
		$s1 = "Software\\Microsoft\\FlashDiskInf" fullword ascii
		$s2 = ".petite" fullword ascii
		$s3 = "MicrosoftFlashExit" fullword ascii
		$s4 = "MicrosoftFlashHaveExit" fullword ascii
		$s5 = "MicrosoftFlashHaveAck" fullword ascii
		$s6 = "\\driver32" ascii
		$s7 = "MicrosoftFlashZJ" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
