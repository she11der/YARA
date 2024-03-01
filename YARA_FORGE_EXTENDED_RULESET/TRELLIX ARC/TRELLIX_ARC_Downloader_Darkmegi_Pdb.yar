rule TRELLIX_ARC_Downloader_Darkmegi_Pdb : DOWNLOADER FILE
{
	meta:
		description = "Rule to detect DarkMegi downloader based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "3ccc3685-e05b-5620-9198-24733fb1e7eb"
		date = "2013-03-06"
		modified = "2020-08-14"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkmegi"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_downloader_darkmegi.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "bf849b1e8f170142176d2a3b4f0f34b40c16d0870833569824809b5c65b99fc1"
		logic_hash = "47faf8c5296e651f82726a6e8a7843dfa0f98e7be7257d2c03efcff550f52140"
		score = 75
		quality = 70
		tags = "DOWNLOADER, FILE"
		rule_version = "v1"
		malware_type = "downloader"
		malware_family = "Downloader:W32/DarkMegi"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\RKTDOW~1\\RKTDRI~1\\RKTDRI~1\\objchk\\i386\\RktDriver.pdb"

	condition:
		uint16(0)==0x5a4d and filesize >20000KB and any of them
}
