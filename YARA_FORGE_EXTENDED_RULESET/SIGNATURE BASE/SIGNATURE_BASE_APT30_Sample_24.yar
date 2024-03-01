rule SIGNATURE_BASE_APT30_Sample_24 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "aed2201d-b557-56ec-aa53-fff5b1e17dbd"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L639-L658"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "572caa09f2b600daa941c60db1fc410bef8d1771"
		logic_hash = "9d550fd0225f1c4e3b16ae53648644d7bb5c80e99e2a1a3d199e51c7219c2e94"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "dizhi.gif" fullword ascii
		$s3 = "Mozilla/4.0" fullword ascii
		$s4 = "lyeagles" fullword ascii
		$s6 = "HHOSTR" ascii
		$s7 = "#MicrosoftHaveAck7" ascii
		$s8 = "iexplore." fullword ascii
		$s17 = "ModuleH" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
