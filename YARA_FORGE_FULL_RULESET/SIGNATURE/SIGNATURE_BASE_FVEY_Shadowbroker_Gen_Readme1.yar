rule SIGNATURE_BASE_FVEY_Shadowbroker_Gen_Readme1
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "1f5e3ab1-e0d1-589e-8c18-60c4ad07ee6e"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fvey_shadowbroker_dec16.yar#L356-L372"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "171d3df191e5c9ae4a4afc3a878cc25548238046b8c4c52dbb9ca4431aae45b0"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "4b236b066ac7b8386a13270dcb7fdff2dda81365d03f53867eb72e29d5e496de"
		hash2 = "64c24bbf42f15dcac04371aef756feabb7330f436c20f33cb25fbc8d0ff014c7"
		hash3 = "a237a2bd6aec429f9941d6de632aeb9729880aa3d5f6f87cf33a76d6caa30619"

	strings:
		$x1 = "ls -latr /tp/med/archive/collect/siemens_msc_isb01/.tmp_ncr/*.MSC | head -10" fullword ascii

	condition:
		1 of them
}
