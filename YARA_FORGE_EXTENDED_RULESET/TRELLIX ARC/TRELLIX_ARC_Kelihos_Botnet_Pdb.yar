rule TRELLIX_ARC_Kelihos_Botnet_Pdb : BOTNET FILE
{
	meta:
		description = "Rule to detect Kelihos malware based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "2b6683a1-ba19-586b-8a92-89d4764efa12"
		date = "2013-09-04"
		modified = "2020-08-14"
		reference = "https://www.malwaretech.com/2017/04/the-kelihos-botnet.html"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_kelhios_botnet_pdb.yar#L1-L26"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "f0a6d09b5f6dbe93a4cf02e120a846073da2afb09604b7c9c12b2e162dfe7090"
		logic_hash = "f60fb85161f86653f390b444d568da24cf07b3be99856230156741e8451e2a3f"
		score = 75
		quality = 70
		tags = "BOTNET, FILE"
		rule_version = "v1"
		malware_type = "botnet"
		malware_family = "Botnet:W32/Kelihos"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Only\\Must\\Not\\And.pdb"
		$pdb1 = "\\To\\Access\\Do.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <1440KB and any of them
}
