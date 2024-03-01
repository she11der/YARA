rule SIGNATURE_BASE_APT_Kaspersky_Duqu2_Samsungprint : FILE
{
	meta:
		description = "Kaspersky APT Report - Duqu2 Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "cc4bc00e-f38b-577f-8f00-637c0549894c"
		date = "2015-06-10"
		modified = "2023-12-05"
		reference = "https://goo.gl/7yKyOj"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_kaspersky_duqu2.yar#L116-L134"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ce39f41eb4506805efca7993d3b0b506ab6776ca"
		logic_hash = "9b2d80cfe3c47ac315b76c773acc3290668e06e4bbd99402e203b72af593fab8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Installer for printer drivers and applications" fullword wide
		$s1 = "msi4_32.dll" fullword wide
		$s2 = "HASHVAL" fullword wide
		$s3 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword wide
		$s4 = "ca.dll" fullword ascii
		$s5 = "Samsung Electronics Co., Ltd." fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <82KB and all of them
}
