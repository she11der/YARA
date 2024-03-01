rule TRELLIX_ARC_Apt_Gauss_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect Gauss based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "209223cc-16e5-5596-8744-21ad71b5ec2a"
		date = "2012-08-14"
		modified = "2020-08-14"
		reference = "https://securelist.com/the-mystery-of-the-encrypted-gauss-payload-5/33561/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/gauss_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "7b0d0612b4ecc889a901115c2e77776ef0ea65c056b283d12e80f863062cea28"
		logic_hash = "cb20c87ea976f395e000f2c631ffd52b09dca2af37adceafe5be72b37f75a997"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Gauss"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$pdb = "\\projects\\gauss\\bin\\release\\winshell.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <550KB and any of them
}
