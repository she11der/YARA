rule SIGNATURE_BASE_APT30_Generic_C : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "25ec8d54-9875-5bf5-abc9-296f18f3c5e5"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L66-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b969565eac3b6f548318aae4edc8d8851f522a6c263bcaf2a466ff0ca9af78a4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8667f635fe089c5e2c666b3fe22eaf3ff8590a69"
		hash2 = "0c4fcef3b583d0ffffc2b14b9297d3a4"
		hash3 = "37aee58655f5859e60ece6b249107b87"
		hash4 = "4154548e1f8e9e7eb39d48a4cd75bcd1"
		hash5 = "a2e0203e665976a13cdffb4416917250"
		hash6 = "b4ae0004094b37a40978ef06f311a75e"
		hash7 = "e39756bc99ee1b05e5ee92a1cdd5faf4"

	strings:
		$s0 = "MYUSER32.dll" fullword ascii
		$s1 = "MYADVAPI32.dll" fullword ascii
		$s2 = "MYWSOCK32.dll" fullword ascii
		$s3 = "MYMSVCRT.dll" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
