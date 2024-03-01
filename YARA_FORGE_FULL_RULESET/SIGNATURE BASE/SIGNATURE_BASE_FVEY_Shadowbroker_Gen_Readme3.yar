rule SIGNATURE_BASE_FVEY_Shadowbroker_Gen_Readme3
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "41cfbf66-fb7d-5815-939f-06b23dfae746"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fvey_shadowbroker_dec16.yar#L391-L411"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "968ec80f26750ac734ad9e296b5afb35867f6c53de1e88f7c8af78daeac24b61"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "18dfd74c3e0bfb1c21127cf3382ba1d9812efdf3e992bd666d513aaf3519f728"
		hash2 = "4b236b066ac7b8386a13270dcb7fdff2dda81365d03f53867eb72e29d5e496de"
		hash3 = "3fe78949a9f3068db953b475177bcad3c76d16169469afd72791b4312f60cfb3"
		hash4 = "64c24bbf42f15dcac04371aef756feabb7330f436c20f33cb25fbc8d0ff014c7"
		hash5 = "a237a2bd6aec429f9941d6de632aeb9729880aa3d5f6f87cf33a76d6caa30619"
		hash6 = "89748906d1c574a75fe030645c7572d7d4145b143025aa74c9b5e2be69df8773"
		hash7 = "f4b728c93dba20a163b59b4790f29aed1078706d2c8b07dc7f4e07a6f3ecbe93"

	strings:
		$s3 = ":%s/CRYPTKEY/CRYPTKEY/g" fullword ascii

	condition:
		1 of them
}
