rule GCTI_Cobaltstrike_Resources_Dnsstager_Bin_V1_47_Through_V4_X
{
	meta:
		description = "Cobalt Strike's resources/dnsstager.bin signature for versions 1.47 to 4.x"
		author = "gssincla@google.com"
		id = "e1b0e368-9bcf-5d9b-b2b3-8414742f213e"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Dnsstager_Bin_v1_47_through_v4_x.yara#L17-L78"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "10f946b88486b690305b87c14c244d7bc741015c3fef1c4625fa7f64917897f1"
		logic_hash = "d4500d8a83a821e1df9e808b17a87c1207d78ea0e03886544a632176fe93ccd0"
		score = 75
		quality = 83
		tags = ""

	strings:
		$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5?
}