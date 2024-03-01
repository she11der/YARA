rule SIGNATURE_BASE_APT30_Sample_7 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "612732d9-8df5-5388-b299-2da4f8118435"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L145-L163"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "868d1f4c106a08bd2e5af4f23139f0e0cd798fba"
		logic_hash = "f7922d795bc92714a9ef4861bc9c4ac9921a73749e3aa1d5f7dbc3c991fe7145"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "datain" fullword ascii
		$s3 = "C:\\Prog" ascii
		$s4 = "$LDDATA$" ascii
		$s5 = "Maybe a Encrypted Flash" fullword ascii
		$s6 = "Jean-loup Gailly" ascii
		$s8 = "deflate 1.1.3 Copyright" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
