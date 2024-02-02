rule GCTI_Cobaltstrike_Resources_Artifact32Svc_Exe_V3_1_V3_2_V3_14_And_V4_X
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe signature for versions 3.1 and 3.2 (with overlap with v3.14 through v4.x)"
		author = "gssincla@google.com"
		id = "732169be-e334-5774-b0ac-54b217a8b681"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Artifact32svc_Exe_v1_49_to_v4_x.yara#L53-L77"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "871390255156ce35221478c7837c52d926dfd581173818620b738b4b029e6fd9"
		logic_hash = "b55211fc2dbe100edb19c3f3a000be513144e3556c4bce8a29a3c0b77451ba96"
		score = 75
		quality = 85
		tags = ""

	strings:
		$decoderFunc = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 }

	condition:
		$decoderFunc
}