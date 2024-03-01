rule TRELLIX_ARC_Malw_Cutwail_Pdb : BOTNET FILE
{
	meta:
		description = "Rule to detect cutwail based on the PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "62058ff9-acb5-5f71-b6bb-4c64e51442ba"
		date = "2008-04-16"
		modified = "2020-08-14"
		reference = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/CUTWAIL"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_cutwail.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "d702f823eefb50d9ea5b336c638f65a40c2342f8eb88278da60aa8a498c75010"
		logic_hash = "f53626e6085509ddf9268b69e54a138e64cd5d3fbad119e6e9473179decd7927"
		score = 75
		quality = 70
		tags = "BOTNET, FILE"
		rule_version = "v1"
		malware_type = "botnet"
		malware_family = "Botnet:W32/Cutwail"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\0bulknet\\FLASH\\Release\\flashldr.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <440KB and any of them
}
