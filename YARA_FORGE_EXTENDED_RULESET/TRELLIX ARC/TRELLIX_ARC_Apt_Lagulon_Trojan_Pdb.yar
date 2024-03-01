rule TRELLIX_ARC_Apt_Lagulon_Trojan_Pdb : TROJAN FILE
{
	meta:
		description = "Rule to detect trojan Lagulon based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "a31a465d-1f16-5c3e-a62d-ea15c11253c3"
		date = "2013-08-31"
		modified = "2020-08-14"
		reference = "https://www.cylance.com/operation-cleaver-cylance"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_lagulon_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "e401340020688cdd0f5051b7553815eee6bc04a5a962900883f1b3676bf1de53"
		logic_hash = "dad04c2deb990f253f952b768b74349dc9afb5f6db91ea3afff889f4c9f3230b"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "trojan"
		malware_family = "Trojan:W32/lagulon"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$pdb = "\\proj\\wndTest\\Release\\wndTest.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <50KB and any of them
}
