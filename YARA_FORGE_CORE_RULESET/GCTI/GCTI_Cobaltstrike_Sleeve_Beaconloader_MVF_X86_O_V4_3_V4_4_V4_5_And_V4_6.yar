rule GCTI_Cobaltstrike_Sleeve_Beaconloader_MVF_X86_O_V4_3_V4_4_V4_5_And_V4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x86.o (MapViewOfFile) Versions 4.3 through at least 4.6"
		author = "gssincla@google.com"
		id = "3f7c0553-989e-53e7-87a9-3fa1c47f4b62"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara#L61-L111"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "cded3791caffbb921e2afa2de4c04546067c3148c187780066e8757e67841b44"
		logic_hash = "dd831fb01a403213c06e3d07daf3da5f56655619a686149f9d4beec2331fe6ca"
		score = 75
		quality = 85
		tags = ""

	strings:
		$core_sig = {
      C6 45 EC 4D
      C6 45 ED 61
      C6 45 EE 70
      C6 45 EF 56
      C6 45 F0 69
      C6 45 F1 65
      C6 45 F2 77
      C6 45 F3 4F
      C6 45 F4 66
      C6 45 F5 46
      C6 45 F6 69
      C6 45 F7 6C
      C6 45 F8 65
      C6 45 F9 00
    }

	condition:
		all of them
}
