rule SIGNATURE_BASE_APT30_Generic_D : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "9b8d8a60-a357-5cfd-8ff1-6264144ad7be"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L702-L725"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ff39fc7643441652ec0cdf2f84c7827d326ddb5f01451b3857cfc4015eb01467"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "35dfb55f419f476a54241f46e624a1a4"
		hash2 = "4fffcbdd4804f6952e0daf2d67507946"
		hash3 = "597805832d45d522c4882f21db800ecf"
		hash4 = "6bd422d56e85024e67cc12207e330984"
		hash5 = "82e13f3031130bd9d567c46a9c71ef2b"
		hash6 = "b79d87ff6de654130da95c73f66c15fa"

	strings:
		$s0 = "Windows Security Service Feedback" fullword wide
		$s1 = "wssfmgr.exe" fullword wide
		$s2 = "\\rb.htm" ascii
		$s3 = "rb.htm" fullword ascii
		$s4 = "cook5" ascii
		$s5 = "5, 4, 2600, 0" fullword wide

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
