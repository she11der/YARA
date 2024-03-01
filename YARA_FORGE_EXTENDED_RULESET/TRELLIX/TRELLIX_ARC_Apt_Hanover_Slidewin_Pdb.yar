rule TRELLIX_ARC_Apt_Hanover_Slidewin_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect hanover slidewin samples"
		author = "Marc Rivero | McAfee ATR Team"
		id = "aefa1a2b-6a6f-5209-b1e2-90f1817442da"
		date = "2012-01-05"
		modified = "2020-08-14"
		reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_hangover.yar#L202-L229"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "89b80267f9c7fc291474e5751c2e42838fdab7a5cbd50a322ed8f8efc3d2ce83"
		logic_hash = "28922d75109cf3da4807e08588e076f1496c14ea462a1c8dedb1d1a734f1fb48"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Hanover"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Users\\God\\Desktop\\ThreadScheduler-aapnews-Catroot2\\Release\\ThreadScheduler.pdb"
		$pdb1 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-hostzi\\Release\\slidebar.pdb"
		$pdb2 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-spectram\\Release\\slidebar.pdb"
		$pdb3 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-zendossier\\Release\\slidebar.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <100KB and any of them
}
