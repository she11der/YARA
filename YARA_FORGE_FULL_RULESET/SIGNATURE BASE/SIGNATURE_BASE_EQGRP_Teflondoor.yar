import "pe"

rule SIGNATURE_BASE_EQGRP_Teflondoor : FILE
{
	meta:
		description = "Detects tool from EQGRP toolset - file teflondoor.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "188f9ef1-5524-50be-ac62-91cb9726b155"
		date = "2016-08-15"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L52-L73"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "38be3cfa638509d539bf4ada3b5c7e44e01ee4cfb74a53a76cd2f4287c5a56f5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "%s: abort.  Code is %d.  Message is '%s'" fullword ascii
		$x2 = "%s: %li b (%li%%)" fullword ascii
		$s1 = "no winsock" fullword ascii
		$s2 = "%s: %s file '%s'" fullword ascii
		$s3 = "peer: connect" fullword ascii
		$s4 = "read: write" fullword ascii
		$s5 = "%s: done!" fullword ascii
		$s6 = "%s: %li b" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and 1 of ($x*) and 3 of them
}
