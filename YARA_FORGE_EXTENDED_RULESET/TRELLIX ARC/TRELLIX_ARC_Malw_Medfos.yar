rule TRELLIX_ARC_Malw_Medfos : TROJAN FILE
{
	meta:
		description = "Rule to detect Medfos trojan based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "07ad0227-ca8f-5071-8ef7-8c3e087fcc35"
		date = "2013-04-19"
		modified = "2020-08-14"
		reference = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=win32%2Fmedfos"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_medfos_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "3582e242f62598445ca297c389cae532613afccf48b16e9c1dcf1bfedaa6e14f"
		logic_hash = "1726462a806f5cb3f0b80596623cebc51a7a9f866ded0cb59ea1c43034ce2819"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "trojan"
		malware_family = "Trojan:W32/Medfos"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\som\\bytguqne\\jzexsaf\\gyin.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <150KB and any of them
}
