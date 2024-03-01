rule TRELLIX_ARC_Malw_Mangzamel_Trojan : TROJAN FILE
{
	meta:
		description = "Rule to detect Mangzamel  trojan based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "ca77180f-6133-5edb-a36b-78bc6f18d80c"
		date = "2014-06-25"
		modified = "2020-08-14"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mangzamel"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_mangzamel_trojan_pdb.yar#L1-L26"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "4324580ea162a636b7db1efb3a3ba38ce772b7168b4eb3a149df880a47bd72b7"
		logic_hash = "bab103c671445e0ea916fae290689d30d45021bdca58a495ebd3d6ca9ca55051"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "trojan"
		malware_family = "Trojan:W32/Mangzamel"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\svn\\sys\\binary\\i386\\agony.pdb"
		$pdb1 = "\\Windows\\i386\\ndisdrv.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <360KB and any of them
}
