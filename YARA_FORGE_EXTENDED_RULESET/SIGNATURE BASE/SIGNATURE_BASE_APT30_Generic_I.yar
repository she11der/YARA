rule SIGNATURE_BASE_APT30_Generic_I : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "55046e1a-731a-5418-9a7a-4fe1611c77d0"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L224-L240"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e6f0edcbf6e0590c8b4a558142053d5938e86d13d65787f02336dc2a173d5963"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fe211c7a081c1dac46e3935f7c614549"
		hash2 = "8c9db773d387bf9b3f2b6a532e4c937c"

	strings:
		$s0 = "Copyright 2012 Google Inc. All rights reserved." fullword wide
		$s1 = "(Prxy%c-%s:%u)" fullword ascii
		$s2 = "Google Inc." fullword wide

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
