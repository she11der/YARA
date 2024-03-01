rule SIGNATURE_BASE_APT30_Microfost : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "19231001-1da3-5be6-8275-03c9fc7c6377"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L871-L885"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "57169cb4b8ef7a0d7ebd7aa039d1a1efd6eb639e"
		logic_hash = "1fe5be3a88859fd3d485adfba92cf117afedc739bd0a46c039124919c3b81361"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Copyright (c) 2007 Microfost All Rights Reserved" fullword wide
		$s2 = "Microfost" fullword wide

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
