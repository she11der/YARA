rule GCTI_Cobaltstrike_Resources_Httpsstager_Bin_V2_5_Through_V4_X
{
	meta:
		description = "Cobalt Strike's resources/httpsstager.bin signature for versions 2.5 to 4.x"
		author = "gssincla@google.com"
		id = "f45aa40a-3936-50f9-a60e-de7181862d19"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Httpsstager_Bin_v2_5_through_v4_x.yara#L17-L95"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "5ebe813a4c899b037ac0ee0962a439833964a7459b7a70f275ac73ea475705b3"
		logic_hash = "d2f722809a59faf8ecd85e46eadf58bf23ba5f515ad9c949843f1e6bfeec1fbf"
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
		$InternetSetOptionA = {
			6A 04
			5? 
			6A 1F
			5? 
			68 75 46 9E 86
			FF  
		}

	condition:
		$apiLocator and $InternetSetOptionA
}