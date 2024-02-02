rule GCTI_Cobaltstrike_Sleeve_Beacon_Dll_V4_3_V4_4_V4_5_And_V4_6
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.3 and 4.4"
		author = "gssincla@google.com"
		id = "976e087c-f371-5fc6-85f8-9c803a91f549"
		date = "2022-11-18"
		modified = "2023-12-04"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Beacon_Dll_All_Versions_MemEnabled.yara#L936-L967"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "51490c01c72c821f476727c26fbbc85bdbc41464f95b28cdc577e5701790845f"
		logic_hash = "6608a84c4fd3bf77fd5b426da8be250d8b99878bd746fa23789f4791a164ce33"
		score = 75
		quality = 85
		tags = ""
		rs2 = "78a6fbefa677eeee29d1af4a294ee57319221b329a2fe254442f5708858b37dc"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 65 0F 87 47 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}