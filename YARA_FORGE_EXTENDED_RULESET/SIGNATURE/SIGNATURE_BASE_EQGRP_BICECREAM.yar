import "pe"

rule SIGNATURE_BASE_EQGRP_BICECREAM : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file BICECREAM-2140"
		author = "Florian Roth (Nextron Systems)"
		id = "a10819ae-db48-5d30-8e2e-2e4fe33e005b"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L761-L782"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "adaa6b7d4bf9e6f95fbae781382e72afc07993582473cbee7139a93df0fe3283"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4842076af9ba49e6dfae21cf39847b4172c06a0bd3d2f1ca6f30622e14b77210"

	strings:
		$s1 = "Could not connect to target device: %s:%d. Please check IP address." fullword ascii
		$s2 = "command data size is invalid for an exec cmd" fullword ascii
		$s3 = "A script was specified but target is not a PPC405-based NetScreen (NS5XT, NS25, and NS50). Executing scripts is supported but ma" ascii
		$s4 = "Execute 0x%08x with args (%08x, %08x, %08x, %08x): [y/n]" fullword ascii
		$s5 = "Execute 0x%08x with args (%08x, %08x, %08x): [y/n]" fullword ascii
		$s6 = "[%d] Execute code." fullword ascii
		$s7 = "Execute 0x%08x with args (%08x): [y/n]" fullword ascii
		$s8 = "dump_value_LHASH_DOALL_ARG" fullword ascii
		$s9 = "Eggcode is complete. Pass execution to it? [y/n]" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <5000KB and 2 of them ) or (5 of them )
}
