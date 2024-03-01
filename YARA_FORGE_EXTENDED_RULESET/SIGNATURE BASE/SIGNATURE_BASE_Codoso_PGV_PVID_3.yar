rule SIGNATURE_BASE_Codoso_PGV_PVID_3
{
	meta:
		description = "Detects Codoso APT PGV PVID Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "08003dba-1201-5f74-9edd-ea321bb26e99"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_codoso.yar#L295-L314"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "371a91b08747b8025baba79797baf9f29487f9c3541f27fc2c2716b531d30b54"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "126fbdcfed1dfb31865d4b18db2fb963f49df838bf66922fea0c37e06666aee1"
		hash2 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash3 = "8a56b476d792983aea0199ee3226f0d04792b70a1c1f05f399cb6e4ce8a38761"
		hash4 = "b2950f2e09f5356e985c38b284ea52175d21feee12e582d674c0da2233b1feb1"
		hash5 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
		hash6 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"

	strings:
		$x1 = "Copyright (C) Microsoft Corporation.  All rights reserved.(C) 2012" fullword wide

	condition:
		$x1
}
