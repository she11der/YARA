rule SIGNATURE_BASE_APT30_Sample_10 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L264-L283"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "eb518cda3c4f4e6938aaaee07f1f7db8ee91c901"
		logic_hash = "5a6bd8223fbce133bd11b903edfd7f8ff5a436e26a47c048a5ac606ad4a0b564"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Version 4.7.3001" fullword wide
		$s1 = "Copyright (c) Microsoft Corporation 2004" fullword wide
		$s2 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the U" wide
		$s3 = "!! Use Connect Method !!" fullword ascii
		$s4 = "(Prxy%c-%s:%u)" fullword ascii
		$s5 = "msmsgs" fullword wide
		$s18 = "(Prxy-No)" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
