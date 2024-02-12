rule GCTI_Cobaltstrike_Resources_Bypassuac_Dll_V1_49_To_V3_14_And_Sleeve_Bypassuac_Dll_V4_0_To_V4_X
{
	meta:
		description = "Cobalt Strike's resources/bypassuac(-x86).dll from v1.49 to v3.14 (32-bit version) and sleeve/bypassuac.dll from v4.0 to at least v4.4"
		author = "gssincla@google.com"
		id = "614046b5-cf81-56a5-8824-b3a7e14a8ed5"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Bypassuac_Dll_v1_49_to_v3_14_and_Sleeve_Bypassuac_Dll_v4_0_to_v4_x.yara#L17-L94"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "91d12e1d09a642feedee5da966e1c15a2c5aea90c79ac796e267053e466df365"
		logic_hash = "7d59c0286f1936e386519a919472d01581b68a8167c89bd3cd3108d45251119a"
		score = 75
		quality = 85
		tags = ""

	strings:
		$deleteFileCOM = {
			A1 [4]
			6A 00
			8B ?? 
			5? 
			5? 
			FF ?? 48 
			85 ?? 
			75 ?? 
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}
		$copyFileCOM = {
			A1 [4]
			6A 00
			FF [2]
			8B ?? 
			FF [5]
			FF [5]
			5? 
			FF ?? 40 
			85 ?? 
			[2 - 6]
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}

	condition:
		all of them
}