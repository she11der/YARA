rule GCTI_Cobaltstrike_Resources_Httpstager64_Bin_V3_2_Through_V4_X
{
	meta:
		description = "Cobalt Strike's resources/httpstager64.bin signature for versions v3.2 to v4.x"
		author = "gssincla@google.com"
		id = "5530dce8-e5a1-5133-9b05-464e3397084a"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Httpstager64_Bin_v3_2_through_v4_x.yara#L17-L85"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "ad93d1ee561bc25be4a96652942f698eac9b133d8b35ab7e7d3489a25f1d1e76"
		logic_hash = "23666169565c6b3e5fa71767dc31096e7a25be049eeab16b074053d76c97c70b"
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
		$postInternetOpenJmp = {
			41 ?? 3A 56 79 A7
			FF ??
			EB 
		}

	condition:
		$apiLocator and $postInternetOpenJmp
}
