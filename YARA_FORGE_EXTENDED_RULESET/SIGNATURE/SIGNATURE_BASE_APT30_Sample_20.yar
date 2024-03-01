rule SIGNATURE_BASE_APT30_Sample_20 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "91246101-246b-5da9-9e55-7f361d1f6437"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L537-L557"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b1c37632e604a5d1f430c9351f87eb9e8ea911c0"
		logic_hash = "f94cbd4b8e7ba302db9ac4ef3617bd68aa0aa1ee3cfc6dfee4621223bbdae3c5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "dizhi.gif" fullword ascii
		$s2 = "Mozilla/u" ascii
		$s3 = "XicrosoftHaveAck" ascii
		$s4 = "flyeagles" ascii
		$s10 = "iexplore." ascii
		$s13 = "WindowsGV" fullword ascii
		$s16 = "CatePipe" fullword ascii
		$s17 = "'QWERTY:/webpage3" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
