rule TRELLIX_ARC_Apt_Hanover_Linog_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect hanover linog samples based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "2f4d30ad-aadc-5c90-8234-d1b5802f4781"
		date = "2012-01-05"
		modified = "2020-08-14"
		reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_hangover.yar#L108-L132"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "f6319fd0e1d3b9d3694c46f80208e70b389e7dcc6aaad2508b80575c604c5dba"
		logic_hash = "3aebafc80ca2e187bdcae3750162d94ce9419988ffd451ba4762b2d299a04ed7"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Hanover"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Users\\hp\\Desktop\\download\\Release\\download.pdb"
		$pdb1 = "\\Backup-HP-ABCD-PC\\download\\Release\\download.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <165KB and any of them
}
