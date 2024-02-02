rule GCTI_Cobaltstrike_Resources_Artifact64_V3_14_To_V4_X
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.exe,.dll,svc.exe,svcbig.exe,big.exe,big.dll,.x64.dll,big.x64.dll} and resource/artifactuac(alt)64.exe signature for versions v3.14 through v4.x"
		author = "gssincla@google.com"
		id = "1c7731d3-429b-57aa-9c17-8de7d0841b1e"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Artifact64_v1_49_to_v4_x.yara#L86-L128"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "decfcca0018f2cec4a200ea057c804bb357300a67c6393b097d52881527b1c44"
		logic_hash = "af8ba6ba62bf1179510b0940e60f893f61b3ba10c81001dd90fe4c3521e56a37"
		score = 75
		quality = 85
		tags = ""

	strings:
		$fmtBuilder = {
			41 ?? 5C 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 65 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 69 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 2E 00 00 00
			89 [3]
			48 [6]
			E8
}