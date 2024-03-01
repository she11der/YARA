rule TRELLIX_ARC_Apt_Hanover_Appinbot_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect hanover appinbot samples based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "fb201000-ca8b-57e0-b560-5082477d8ee7"
		date = "2012-01-05"
		modified = "2020-08-14"
		reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_hangover.yar#L41-L77"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "6ad56d64444fa76e1ad43a8c260c493b9086d4116eb18af630e65d3fd39bf6d6"
		logic_hash = "56cdd22efd81bcdda445242257b2418c6941bf9e5e68065d8b8d73d0f9c27df5"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Hanover"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\BNaga\\backup_28_09_2010\\threads tut\\pen-backup\\BB_FUD_23\\Copy of client\\Copy of client\\appinbot_1.2_120308\\Build\\Win32\\Release\\appinclient.pdb"
		$pdb1 = "\\BNaga\\SCode\\BOT\\MATRIX_1.2.2.0\\appinbot_1.2_120308\\Build\\Win32\\Release\\deleter.pdb"
		$pdb2 = "\\Documents and Settings\\Admin\\Desktop\\appinbot_1.2_120308\\appinclient\\Build\\Win32\\Release\\appinclient.pdb"
		$pdb3 = "\\Documents and Settings\\Administrator\\Desktop\\Backup\\17_8_2011\\MATRIX_1.3.4\\ CLIENT\\Build\\Win32\\Release\\appinclient.pdb"
		$pdb4 = "\\Documents and Settings\\Administrator\\Desktop\\Backup\\17_8_2011\\MATRIX_1.3.4\\ MATRIX_1.3.4\\CLIENT\\Build\\Win32\\Release\\appinclient.pdb"
		$pdb5 = "\\Documents and Settings\\Administrator\\Desktop\\Backup\\17_8_2011\\MATRIX_1.3.4\\MATRIX_1.3.4\\ CLIENT\\Build\\Win32\\Release\\deleter.pdb"
		$pdb6 = "\\pen-backup\\Copy of client\\Copy of client\\appinbot_1.2_120308\\Build\\Win32\\Release\\appinclient.pdb"
		$pdb7 = "\\pen-backup\\Copy of client\\Copy of client\\appinbot_1.2_120308\\Build\\Win32\\Release\\deleter.pdb"
		$pdb8 = "\\temp\\elance\\PROTOCOL_1.2\\Build\\Win32\\Release\\deleter.pdb"
		$pdb9 = "\\Users\\PRED@TOR\\Desktop\\appinbot_1.2_120308\\Build\\Win32\\Release\\deleter.pdb"
		$pdb10 = "\\Users\\PRED@TOR\\Desktop\\MODIFIED PROJECT LAB\\admin\\Build\\Win32\\Release\\appinclient.pdb"
		$pdb11 = "\\Desktop backup\\Copy\\appinbot_1.2_120308\\Build\\Win32\\Release\\appinclient.pdb"
		$pdb12 = "\\Datahelp\\SCode\\BOT\\MATRIX_1.3.3\\CLIENT\\Build\\Win32\\Release\\appinclient.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <440KB and any of them
}
