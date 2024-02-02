rule GCTI_Cobaltstrike_Sleeve_Beacon_Dll_V4_7_Suspected
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.7 (suspected, not confirmed)"
		author = "gssincla@google.com"
		id = "4b6f90dd-69f3-5555-9195-6a0aed0fff58"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L969-L1002"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "da9e91b3d8df3d53425dd298778782be3bdcda40037bd5c92928395153160549"
		logic_hash = "297ff7c3acfe6f9676dc6c265c548f017f39ccc5217617344e3bccc704ac4c78"
		score = 75
		quality = 85
		tags = ""

	strings:
		$version_sig = { 53 56 48 57 8B F2 83 F8 67 0F 87 5E 03 00 00  }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}