rule SIGNATURE_BASE_APT30_Generic_9 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "cf259f8d-e0a9-579d-93e7-ec14d99faf81"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L1234-L1255"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0b30c2f0bd654371bf3ac4f9d4e700e1544b62a6c0a072d506160c443fc5fe9d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "00d9949832dc3533592c2ce06a403ef19deddce9"
		hash1 = "27a2b981d4c0bb8c3628bfe990db4619ddfdff74"
		hash2 = "05f66492c163ec2a24c6a87c7a43028c5f632437"
		hash3 = "263f094da3f64e72ef8dc3d02be4fb33de1fdb96"

	strings:
		$s0 = "%s\\%s\\$NtRecDoc$" fullword
		$s1 = "%s(%u)%s" fullword
		$s2 = "http://%s%s%s" fullword
		$s3 = "1.9.1.17" fullword wide
		$s4 = "(C)Firefox and Mozilla Developers, according to the MPL 1.1/GPL 2.0/LGPL" wide

	condition:
		filesize <250KB and uint16(0)==0x5A4D and all of them
}
