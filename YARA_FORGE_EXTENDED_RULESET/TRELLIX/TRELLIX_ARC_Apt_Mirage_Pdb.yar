rule TRELLIX_ARC_Apt_Mirage_Pdb : TROJAN FILE
{
	meta:
		description = "Rule to detect Mirage samples based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "49b7623f-a2c9-52e4-8679-d62f6aae99ca"
		date = "2012-09-18"
		modified = "2020-08-14"
		reference = "https://www.secureworks.com/research/the-mirage-campaign"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_mirage_pdb.yar#L1-L26"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "0107a12f05bea4040a467dd5bc5bd130fd8a4206a09135d452875da89f121019"
		logic_hash = "cb88dc787d9964451ea93f5574d9c73ae6a820d81e20d41c3c8ee44c3fee032d"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "trojan"
		malware_family = "Trojan:W32/Mirage"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$pdb = "\\MF-v1.2\\Server\\Debug\\Server.pdb"
		$pdb1 = "\\fox_1.2 20110307\\MF-v1.2\\Server\\Release\\MirageFox_Server.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <150KB and any of them
}
