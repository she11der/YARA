rule TRELLIX_ARC_Backdoor_Kankan_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect kankan PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "6910ecc7-3c31-569b-a7ff-2dcbccff88f9"
		date = "2013-08-01"
		modified = "2020-08-14"
		reference = "https://threatpoint.checkpoint.com/ThreatPortal/threat?threatType=malwarefamily&threatId=650"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_backdoor_kankan_pdb.yar#L1-L27"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "73f9e28d2616ee990762ab8e0a280d513f499a5ab2cae9f8cf467701f810b98a"
		logic_hash = "3d2e45631dfca0e76e98eee4bb5c4ce1631906f497c052d8c41cc37637cb2760"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Kankan"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Projects\\OfficeAddin\\INPEnhSvc\\Release\\INPEnhSvc.pdb"
		$pdb1 = "\\Projects\\OfficeAddin\\OfficeAddin\\Release\\INPEn.pdb"
		$pdb2 = "\\Projects\\OfficeAddinXJ\\VOCEnhUD\\Release\\VOCEnhUD.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <500KB and any of them
}
