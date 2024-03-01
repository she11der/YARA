rule TRELLIX_ARC_Dridex_P2P_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect Dridex P2P based on the PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "57350c96-877e-57de-9465-df9f7eb6d656"
		date = "2014-11-29"
		modified = "2020-08-14"
		reference = "https://www.us-cert.gov/ncas/alerts/aa19-339a"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_dridex_p2p_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "5345a9405212f3b8ef565d5d793e407ae8db964865a85c97e096295ba3f39a78"
		logic_hash = "c9c4db48435203cdb882eef8082efd8424bd13f1aa512cfb3082f365b9bc6e83"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Dridex"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\c0da\\j.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <400KB and any of them
}
