rule TRELLIX_ARC_Dropper_Demekaf_Pdb : DROPPER FILE
{
	meta:
		description = "Rule to detect Demekaf dropper based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "b49f42c1-d737-5afa-b547-7268e4cde360"
		date = "2011-03-26"
		modified = "2020-08-14"
		reference = "https://v.virscan.org/Trojan-Dropper.Win32.Demekaf.html"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_dropper_demekaf_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "fab320fceb38ba2c5398debdc828a413a41672ce9745afc0d348a0e96c5de56e"
		logic_hash = "89c0c1da1f8997b12a446c93bbde200e62fac9cab2a9a17147b268d435bdc3b6"
		score = 75
		quality = 70
		tags = "DROPPER, FILE"
		rule_version = "v1"
		malware_type = "dropper"
		malware_family = "Dropper:W32/Demekaf"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\vc\\res\\fake1.19-jpg\\fake\\Release\\fake.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <150KB and any of them
}
