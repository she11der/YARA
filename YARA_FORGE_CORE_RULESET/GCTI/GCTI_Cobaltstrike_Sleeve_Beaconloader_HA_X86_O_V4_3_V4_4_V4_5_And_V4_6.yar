rule GCTI_Cobaltstrike_Sleeve_Beaconloader_HA_X86_O_V4_3_V4_4_V4_5_And_V4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.HA.x86.o (HeapAlloc) Versions 4.3 through at least 4.6"
		author = "gssincla@google.com"
		id = "0ee3fa6f-367c-596f-a3bc-3bcfa61b97aa"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara#L17-L59"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "8e4a1862aa3693f0e9011ade23ad3ba036c76ae8ccfb6585dc19ceb101507dcd"
		logic_hash = "d02257bc556d0b1675997ab6af1b28cf5f498855d6254e3c1cd7eb4a0c4d2715"
		score = 75
		quality = 85
		tags = ""

	strings:
		$core_sig = {
      C6 45 F0 48
      C6 45 F1 65
      C6 45 F2 61
      C6 45 F3 70
      C6 45 F4 41
      C6 45 F5 6C
      C6 45 F6 6C
      C6 45 F7 6F
      C6 45 F8 63
      C6 45 F9 00
    }

	condition:
		all of them
}
