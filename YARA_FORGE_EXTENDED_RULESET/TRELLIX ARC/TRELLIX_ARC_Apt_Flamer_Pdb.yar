rule TRELLIX_ARC_Apt_Flamer_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect Flamer based on the PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "3bbe043d-c0dc-5aa2-b985-800a6d9038fd"
		date = "2012-05-29"
		modified = "2020-08-14"
		reference = "https://www.forcepoint.com/ko/blog/x-labs/flameflamerskywiper-one-most-advanced-malware-found-yet"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/flamer_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "554924ebdde8e68cb8d367b8e9a016c5908640954ec9fb936ece07ac4c5e1b75"
		logic_hash = "3c1d3d015e086cff1f3d5add39397d8ed251b12144b31d8547165cbd0217735c"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Flamer"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Projects\\Jimmy\\jimmydll_v2.0\\JimmyForClan\\Jimmy\\bin\\srelease\\jimmydll\\indsvc32.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <500KB and any of them
}
