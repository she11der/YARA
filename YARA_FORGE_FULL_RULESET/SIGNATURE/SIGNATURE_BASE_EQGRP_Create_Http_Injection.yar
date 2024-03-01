import "pe"

rule SIGNATURE_BASE_EQGRP_Create_Http_Injection : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file create_http_injection.py"
		author = "Florian Roth (Nextron Systems)"
		id = "92b6dad0-c7d8-5522-8fc1-fbd0aae00960"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L784-L802"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3a2ee46c6fec1b7a501e8c0e2963d4873ede89d192d0f4701d051f782e8ece99"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "de52f5621b4f3896d4bd1fb93ee8be827e71a2b189a9f8552b68baed062a992d"

	strings:
		$x1 = "required by SECONDDATE" fullword ascii
		$s1 = "help='Output file name (optional). By default the resulting data is written to stdout.')" fullword ascii
		$s2 = "data = '<html><body onload=\"location.reload(true)\"><iframe src=\"%s\" height=\"1\" width=\"1\" scrolling=\"no\" frameborder=\"" ascii
		$s3 = "version='%prog 1.0'," fullword ascii
		$s4 = "usage='%prog [ ... options ... ] url'," fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <3KB and ($x1 or 2 of them )) or ( all of them )
}
