rule TRELLIX_ARC_Alina_POS_PDB : POS FILE
{
	meta:
		description = "Rule to detect Alina POS"
		author = "Marc Rivero | McAfee ATR Team"
		id = "9588aa10-d5e4-55f4-998c-a01503a53d3a"
		date = "2013-08-08"
		modified = "2020-08-14"
		reference = "https://www.pandasecurity.com/mediacenter/pandalabs/alina-pos-malware/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_alina_pos_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "28b0c52c0630c15adcc857d0957b3b8002a4aeda3c7ec40049014ce33c7f67c3"
		logic_hash = "9bb8260e3a47567e2460dd474fb74e57987e3d79eb30cdbc2a45b88a16ba1ca2"
		score = 75
		quality = 70
		tags = "POS, FILE"
		rule_version = "v1"
		malware_type = "pos"
		malware_family = "Pos:W32/Alina"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Users\\dice\\Desktop\\SRC_adobe\\src\\grab\\Release\\Alina.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <100KB and any of them
}
