rule TRELLIX_ARC_Havex_Backdoor_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect backdoor Havex based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "a667bb4e-8c38-59a6-8ae0-09c44961a687"
		date = "2012-11-17"
		modified = "2020-08-14"
		reference = "https://www.f-secure.com/v-descs/backdoor_w32_havex.shtml"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_backdoor_havex_pdb.yar#L1-L26"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "0f4046be5de15727e8ac786e54ad7230807d26ef86c3e8c0e997ea76ab3de255"
		logic_hash = "dc50475b1ff2194306a0295f71860e4cc5ae7e126daa5d401b98cd2a0aadf1dd"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Havex"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Workspace\\PhalangX 3D\\Src\\Build\\Release\\Phalanx-3d.ServerAgent.pdb"
		$pdb1 = "\\Workspace\\PhalangX 3D\\Src\\Build\\Release\\Tmprovider.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <500KB and any of them
}
