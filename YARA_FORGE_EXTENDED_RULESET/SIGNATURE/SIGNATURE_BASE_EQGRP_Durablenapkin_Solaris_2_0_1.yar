import "pe"

rule SIGNATURE_BASE_EQGRP_Durablenapkin_Solaris_2_0_1 : FILE
{
	meta:
		description = "Detects tool from EQGRP toolset - file durablenapkin.solaris.2.0.1.1"
		author = "Florian Roth (Nextron Systems)"
		id = "7b49a26d-9ee3-5aff-93fc-509239daef28"
		date = "2016-08-15"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L75-L92"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "113f9451d6792511baa168957c643de02f37826b32944ef882f49b68496ec596"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "recv_ack: %s: Service not supplied by provider" fullword ascii
		$s2 = "send_request: putmsg \"%s\": %s" fullword ascii
		$s3 = "port undefined" fullword ascii
		$s4 = "recv_ack: %s getmsg: %s" fullword ascii
		$s5 = ">> %d -- %d" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <40KB and 2 of them )
}
