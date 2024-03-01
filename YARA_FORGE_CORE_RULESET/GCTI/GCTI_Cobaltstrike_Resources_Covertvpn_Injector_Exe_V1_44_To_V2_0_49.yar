rule GCTI_Cobaltstrike_Resources_Covertvpn_Injector_Exe_V1_44_To_V2_0_49
{
	meta:
		description = "Cobalt Strike's resources/covertvpn-injector.exe signature for version v1.44 to v2.0.49"
		author = "gssincla@google.com"
		id = "48485ae2-1d99-5fa8-b8e8-0047e92ef447"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Covertvpn_injector_Exe_v1_44_to_v2_0_49.yara#L17-L116"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "d741751520f46602f5a57d1ed49feaa5789115aeeba7fa4fc7cbb534ee335462"
		logic_hash = "119602efe6243d8c0dc7b8f4468eb9b3be292620920f69dc8a560f900ac7f622"
		score = 75
		quality = 85
		tags = ""

	strings:
		$dropComponentsAndActivateDriver_prologue = {
			C7 04 24 [4]
			E8 [4]
			83 EC 04
			C7 44 24 04 [4]
			89 04 24
			E8 59 14 00 00
			83 EC 08
			89 45 ?? 
			83 7D ?? 00 
			74 ?? 
			E8 [4]
			8D [2]
			89 [3]
			89 04 24
		}
		$dropFile = {
			C7 44 24 04 00 00 00 00
			8B [2]
			89 ?? 24 
			E8 [4]
			83 F8 FF
			74 ?? 
			8B [2]
			89 ?? 24 04 
			C7 04 24 [4]
			E8 [4]
			E9 [4]
			C7 44 24 18 00 00 00 00
			C7 44 24 14 80 01 00 00
			C7 44 24 10 02 00 00 00
			C7 44 24 0C 00 00 00 00
			C7 44 24 08 05 00 00 00
			C7 44 24 04 00 00 00 40
			8B [2]
			89 04 24
			E8 [4]
			83 EC 1C
			89 45 ?? 
		}
		$nfp = "npf.sys" nocase
		$wpcap = "wpcap.dll" nocase

	condition:
		all of them
}
