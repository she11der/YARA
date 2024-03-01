rule TRELLIX_ARC_Festi_Botnet_Pdb : BOTNET FILE
{
	meta:
		description = "Rule to detect the Festi botnet based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "02f4149d-b8ac-5852-8cbe-c47f4cddcba6"
		date = "2013-03-04"
		modified = "2020-08-14"
		reference = "https://www.welivesecurity.com/2012/05/11/king-of-spam-festi-botnet-analysis/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_festi_botnet_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "e55913523f5ae67593681ecb28d0fa1accee6739fdc3d52860615e1bc70dcb99"
		logic_hash = "46e2576900fe94d614a683d4f09079b7ac78654079b2e558d076bcb42db4bf11"
		score = 75
		quality = 70
		tags = "BOTNET, FILE"
		rule_version = "v1"
		malware_type = "botnet"
		malware_family = "Botnet:W32/Festi"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\eclipse\\botnet\\drivers\\Bin\\i386\\kernel.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <80KB and any of them
}
