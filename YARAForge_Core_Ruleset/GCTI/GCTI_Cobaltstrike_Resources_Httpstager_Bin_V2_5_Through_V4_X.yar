rule GCTI_Cobaltstrike_Resources_Httpstager_Bin_V2_5_Through_V4_X
{
	meta:
		description = "Cobalt Strike's resources/httpstager.bin signature for versions 2.5 to 4.x"
		author = "gssincla@google.com"
		id = "86109485-c26c-5c51-8d04-dd1add9a8c57"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Httpstager_Bin_v2_5_through_v4_x.yara#L17-L93"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "a47569af239af092880751d5e7b68d0d8636d9f678f749056e702c9b063df256"
		logic_hash = "3baab08b0118e00432f1869ba5daa4fc6383bfc020119bfbb3047a008c33fe72"
		score = 75
		quality = 85
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