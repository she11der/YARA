rule TRELLIX_ARC_Malw_Likseput_Backdoor_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect Likseput backdoor based on the PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "2193daf8-016b-5f49-97ec-b821c8da22f6"
		date = "2011-03-26"
		modified = "2020-08-14"
		reference = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/bkdr_likseput.e"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_likseput_backdoor_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "993b36370854587f4eef3366562f01ab87bc4f7b88a21f07b44bd5051340386d"
		logic_hash = "2afc4b7e6a5f0d9fed9a075aebaac8157e843c83c55c3f2255431bb6a03459ec"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Likseput"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\work\\code\\2008-7-8muma\\mywork\\winInet_winApplication2009-8-7\\mywork\\aaaaaaa\\Release\\aaaaaaa.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <40KB and any of them
}
