import "pe"

rule SIGNATURE_BASE_EQGRP_Hexdump : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file hexdump.py"
		author = "Florian Roth (Nextron Systems)"
		id = "32a7d845-2fa3-5d8f-84e1-2c7f8d2ca8c8"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L861-L877"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ed36aa5a69296088bdd1db42e6561377294b7bd99c30104b9d4a618d899d7e9a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "95a9a6a8de60d3215c1c9f82d2d8b2640b42f5cabdc8b50bd1f4be2ea9d7575a"

	strings:
		$s1 = "def hexdump(x,lead=\"[+] \",out=sys.stdout):" fullword ascii
		$s2 = "print >>out, \"%s%04x  \" % (lead,i)," fullword ascii
		$s3 = "print >>out, \"%02X\" % ord(x[i+j])," fullword ascii
		$s4 = "print >>out, sane(x[i:i+16])" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <1KB and 2 of ($s*)) or ( all of them )
}
