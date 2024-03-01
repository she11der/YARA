rule GCTI_Cobaltstrike_Resources_Artifact32_V3_14_To_V4_X
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,big.exe,big.dll,bigsvc.exe} signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x and resources/artifact32uac.dll for v3.14 and v4.0"
		author = "gssincla@google.com"
		id = "8a010305-dce5-55f4-b2dd-a736721efe22"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Artifact32_and_Resources_Dropper_v1_45_to_v4_x.yara#L62-L89"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "888bae8d89c03c1d529b04f9e4a051140ce3d7b39bc9ea021ad9fc7c9f467719"
		logic_hash = "fc5c353c568e33df80fa5bab14d11112ca211e269043b83dba8b7d1a6a008a7b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$pushFmtStr = {	C7 [3] 5C 00 00 00 C7 [3] 65 00 00 00 C7 [3] 70 00 00 00 C7 [3] 69 00 00 00 C7 [3] 70 00 00 00 F7 F1 C7 [3] 5C 00 00 00  C7 [3] 2E 00 00 00 C7 [3] 5C 00 00 00 }
		$fmtStr = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"

	condition:
		all of them
}
