rule SIGNATURE_BASE_Ysoserial_Payload_3 : FILE
{
	meta:
		description = "Ysoserial Payloads - from files JavassistWeld1.bin, JBossInterceptors.bin"
		author = "Florian Roth (Nextron Systems)"
		id = "7fb67f48-66dc-57a4-9075-49b2277fa186"
		date = "2017-02-04"
		modified = "2023-12-05"
		reference = "https://github.com/frohoff/ysoserial"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_ysoserial_payloads.yar#L92-L113"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "49491d1c15af8c271fbbb7dedc678a91df74dcb093abe3f056b1ffc2fced99fe"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "f0d2f1095da0164c03a0e801bd50f2f06793fb77938e53b14b57fd690d036929"
		hash2 = "5466d47363e11cd1852807b57d26a828728b9d5a0389214181b966bd0d8d7e56"

	strings:
		$x1 = "ysoserialq" fullword ascii
		$s1 = "targetClassInterceptorMetadatat" fullword ascii
		$s2 = "targetInstancet" fullword ascii
		$s3 = "targetClassL" fullword ascii
		$s4 = "POST_ACTIVATEsr" fullword ascii
		$s5 = "PRE_DESTROYsq" fullword ascii

	condition:
		( uint16(0)==0xedac and filesize <10KB and $x1) or ( all of them )
}
