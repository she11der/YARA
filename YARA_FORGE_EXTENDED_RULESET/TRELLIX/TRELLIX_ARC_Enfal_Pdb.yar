rule TRELLIX_ARC_Enfal_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect Enfal malware"
		author = "Marc Rivero | McAfee ATR Team"
		id = "09b9667c-cf58-5438-958d-19a99fe91e32"
		date = "2013-08-27"
		modified = "2020-08-14"
		reference = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/enfal"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/enfal_pdb.yar#L1-L29"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "6756808313359cbd7c50cd779f809bc9e2d83c08da90dbd80f5157936673d0bf"
		logic_hash = "1f7785a4c54981c3e7cb417718312e0ed82132b9bd9288f7b0f322cbeafbaecd"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Enfal"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Documents and Settings\\Administrator\\My Documents\\Work\\EtenFalcon\\Release\\DllServiceTrojan.pdb"
		$pdb1 = "\\Documents and Settings\\Administrator\\My Documents\\Work\\EtenFalcon\\Release\\ServiceDll.pdb"
		$pdb2 = "\\Release\\ServiceDll.pdb"
		$pdb3 = "\\muma\\0511\\Release\\ServiceDll.pdb"
		$pdb4 = "\\programs\\LuridDownLoader\\LuridDownloader for Falcon\\ServiceDll\\Release\\ServiceDll.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <150KB and any of them
}
