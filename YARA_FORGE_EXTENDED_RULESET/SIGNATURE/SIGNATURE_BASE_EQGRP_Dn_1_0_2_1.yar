import "pe"

rule SIGNATURE_BASE_EQGRP_Dn_1_0_2_1 : FILE
{
	meta:
		description = "Detects tool from EQGRP toolset - file dn.1.0.2.1.linux"
		author = "Florian Roth (Nextron Systems)"
		id = "24b5fb51-2463-56ef-818a-949b4b3bbf5b"
		date = "2016-08-15"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L136-L152"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9b6420401419b280f01f7fc73412386a19e94a57e589a043b231b6a721585c99"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Valid commands are: SMAC, DMAC, INT, PACK, DONE, GO" fullword ascii
		$s2 = "invalid format suggest DMAC=00:00:00:00:00:00" fullword ascii
		$s3 = "SMAC=%02x:%02x:%02x:%02x:%02x:%02x" fullword ascii
		$s4 = "Not everything is set yet" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <30KB and 2 of them )
}
