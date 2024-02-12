rule GCTI_Cobaltstrike_Sleeve_Beaconloader_HA_X64_O_V4_3_V4_4_V4_5_And_V4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.HA.x64.o (HeapAlloc) Versions 4.3 through at least 4.6"
		author = "gssincla@google.com"
		id = "9b16ff13-2d8e-51dc-9f99-6c45eff76feb"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara#L281-L323"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "d64f10d5a486f0f2215774e8ab56087f32bef19ac666e96c5627c70d345a354d"
		logic_hash = "b712a0c218e473f6c64fdead22b291d7fb0bac8ba614adcf1ba6431e854a5e65"
		score = 75
		quality = 85
		tags = ""

	strings:
		$core_sig = {
      C6 44 24 38 48
      C6 44 24 39 65
      C6 44 24 3A 61
      C6 44 24 3B 70
      C6 44 24 3C 41
      C6 44 24 3D 6C
      C6 44 24 3E 6C
      C6 44 24 3F 6F
      C6 44 24 40 63
      C6 44 24 41 00
    }

	condition:
		all of them
}