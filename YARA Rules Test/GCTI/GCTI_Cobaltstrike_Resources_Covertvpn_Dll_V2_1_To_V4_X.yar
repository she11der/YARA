rule GCTI_Cobaltstrike_Resources_Covertvpn_Dll_V2_1_To_V4_X
{
	meta:
		description = "Cobalt Strike's resources/covertvpn.dll signature for version v2.2 to v4.4"
		author = "gssincla@google.com"
		id = "a65b855c-5703-5b9f-bb57-da8ebf898f9b"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Covertvpn_Dll_v2_1_to_v4_x.yara#L17-L120"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "0a452a94d53e54b1df6ba02bc2f02e06d57153aad111171a94ec65c910d22dcf"
		logic_hash = "1f6e4254fdfd4f9b13c2000333aabbb7da90d2df7ee1b12faa6ea3c066351468"
		score = 75
		quality = 85
		tags = ""

	strings:
		$dropComponentsAndActivateDriver_prologue = {
			5? 
			68 [4]
			68 [4]
			C7 [3-5] 00 00 00 00 
			FF 15 [4]
			50
			FF 15 [4]
			8B ?? 
			85 ?? 
			74 ??
			8D [3-5]
			5? 
			FF 15 [4]
			50
}