rule SIGNATURE_BASE_APT30_Sample_18 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L446-L466"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "355436a16d7a2eba8a284b63bb252a8bb1644751"
		logic_hash = "d20f1d1b7b43defc36c7b1f99f14ed9e73e770b6f43d0ad92110cf9178b35b15"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "w.km-nyc.com" fullword ascii
		$s1 = "tscv.exe" fullword ascii
		$s2 = "Exit/app.htm" ascii
		$s3 = "UBD:\\D" ascii
		$s4 = "LastError" ascii
		$s5 = "MicrosoftHaveAck" ascii
		$s7 = "HHOSTR" ascii
		$s20 = "XPL0RE." ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
