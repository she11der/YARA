rule GCTI_Cobaltstrike_Sleeve_Beaconloader_X86_O_V4_3_V4_4_V4_5_And_V4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.x86.o Versions 4.3 through at least 4.6"
		author = "gssincla@google.com"
		id = "32a47966-f3bb-52c3-a977-82a1b09ddf2c"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara#L196-L276"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		logic_hash = "cab5441ce7d919101fc04aa469e77b71a4c444443e44c752f18cbbc5b17ed5c2"
		score = 75
		quality = 85
		tags = ""

	strings:
		$core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }
		$deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }

	condition:
		$core_sig and not $deobfuscator
}
