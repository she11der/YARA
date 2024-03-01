rule TRELLIX_ARC_Apt_Miniasp_Pdb : TROJAN FILE
{
	meta:
		description = "Rule to detect MiniASP based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "2e7e2990-5e7f-52b0-884a-fcb54b2f5488"
		date = "2012-07-12"
		modified = "2020-08-14"
		reference = "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_MiniASP_pdb.yar#L1-L26"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "42334f2119069b8c0ececfb14a7030e480b5d18ca1cc35f1ceaee847bc040e53"
		logic_hash = "8ee6f93aaae2c48cc5835269fd526371040cd33cc309220f92a150444ba21055"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "trojan"
		malware_family = "Trojan:W32/MiniASP"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Project\\mm\\Wininet\\Attack\\MiniAsp4\\Release\\MiniAsp.pdb"
		$pdb1 = "\\XiaoME\\AiH\\20120410\\Attack\\MiniAsp3\\Release\\MiniAsp.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <80KB and any of them
}
