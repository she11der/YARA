import "pe"

rule SIGNATURE_BASE_EQGRP_Bpfcreator_RHEL4 : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file BpfCreator-RHEL4"
		author = "Florian Roth (Nextron Systems)"
		id = "476185f2-b093-5fb9-8604-891e96fe52a9"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L825-L842"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "8586425b13355170137d66fe8d52ed98982d7c5699b26a8c0132f107b4af43d8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "bd7303393409623cabf0fcf2127a0b81fae52fe40a0d2b8db0f9f092902bbd92"

	strings:
		$s1 = "usage %s \"<tcpdump pcap string>\" <outfile>" fullword ascii
		$s2 = "error reading dump file: %s" fullword ascii
		$s3 = "truncated dump file; tried to read %u captured bytes, only got %lu" fullword ascii
		$s4 = "%s: link-layer type %d isn't supported in savefiles" fullword ascii
		$s5 = "DLT %d is not one of the DLTs supported by this device" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <2000KB and all of them )
}
