rule SIGNATURE_BASE_APT30_Sample_3 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "62e81385-26f5-545d-92ff-6604ff4d0186"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L47-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d0320144e65c9af0052f8dee0419e8deed91b61b"
		logic_hash = "ee61ec1fdf27fa21bcc235fce0ab8dc74968b39a747648ce828fb4826cf1d234"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "Software\\Mic" ascii
		$s6 = "HHOSTR" ascii
		$s9 = "ThEugh" fullword ascii
		$s10 = "Moziea/" ascii
		$s12 = "%s%s(X-" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
