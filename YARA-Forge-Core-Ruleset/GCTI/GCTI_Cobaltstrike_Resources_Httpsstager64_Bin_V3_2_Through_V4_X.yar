rule GCTI_Cobaltstrike_Resources_Httpsstager64_Bin_V3_2_Through_V4_X
{
	meta:
		description = "Cobalt Strike's resources/httpsstager64.bin signature for versions v3.2 to v4.x"
		author = "gssincla@google.com"
		id = "c16e73fc-484a-5f7e-8127-d85a0254d842"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Httpsstager64_Bin_v3_2_through_v4_x.yara#L17-L90"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "109b8c55816ddc0defff360c93e8a07019ac812dd1a42209ea7e95ba79b5a573"
		logic_hash = "4889a23c1f2780044b9fb2a0207676d57e82e6c1275614b684a5a9cbe984b761"
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
		$InternetSetOptionA = {
			BA 1F 00 00 00
			6A 00
			68 80 33 00 00
			49 [2]
			41 ?? 04 00 00 00
			41 ?? 75 46 9E 86
		}

	condition:
		$apiLocator and $InternetSetOptionA
}