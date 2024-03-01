rule SIGNATURE_BASE_APT30_Sample_25 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "8b2f2ba2-e9cc-5b3c-8af9-4217d662bc3f"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L660-L679"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "44a21c8b3147fabc668fee968b62783aa9d90351"
		logic_hash = "86945188f888762ae585463df7cfb6e5fed30d0fcfcca4e642aedf07a0193ae7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "C:\\WINDOWS" fullword ascii
		$s2 = "aragua" fullword ascii
		$s4 = "\\driver32\\7$" ascii
		$s8 = "System V" fullword ascii
		$s9 = "Compu~r" fullword ascii
		$s10 = "PROGRAM L" fullword ascii
		$s18 = "GPRTMAX" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
