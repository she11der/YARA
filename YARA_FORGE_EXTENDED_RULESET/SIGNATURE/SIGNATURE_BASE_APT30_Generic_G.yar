rule SIGNATURE_BASE_APT30_Generic_G : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "34269de3-4559-58a5-a621-0ad72857dc9e"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L468-L489"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "1612b392d6145bfb0c43f8a48d78c75f"
		hash = "53f1358cbc298da96ec56e9a08851b4b"
		hash = "c2acc9fc9b0f050ec2103d3ba9cb11c0"
		hash = "f18be055fae2490221c926e2ad55ab11"
		logic_hash = "6926d73839958acd06835c1943edb150a0f60cdc269fac053531a0e0483e0521"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "%s\\%s\\%s=%s" fullword ascii
		$s1 = "Copy File %s OK!" fullword ascii
		$s2 = "%s Space:%uM,FreeSpace:%uM" fullword ascii
		$s4 = "open=%s" fullword ascii
		$s5 = "Maybe a Encrypted Flash Disk" fullword ascii
		$s12 = "%04u-%02u-%02u %02u:%02u:%02u" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
