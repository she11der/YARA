rule GCTI_Cobaltstrike_Resources_Bind64_Bin_V2_5_Through_V4_X
{
	meta:
		description = "Cobalt Strike's resources/bind64.bin signature for versions v2.5 to v4.x"
		author = "gssincla@google.com"
		id = "a01e7bc3-40e9-5f87-8fd6-926972be273b"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Bind64_Bin_v2_5_through_v4_x.yara#L17-L109"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "5dd136f5674f66363ea6463fd315e06690d6cb10e3cc516f2d378df63382955d"
		logic_hash = "ba79abc5cfeaccb94699c0d85c16b2ddf6820bc148c0fd1c9b33c07222e36cb6"
		score = 75
		quality = 85
		tags = ""

	strings:
		$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48
}