rule TRELLIX_ARC_Apt_Elise_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect Elise APT based on the PDB reference"
		author = "Marc Rivero | McAfee ATR Team"
		id = "cc8dd203-baad-5800-ba2c-f9c47d8ca6f0"
		date = "2017-05-31"
		modified = "2020-08-14"
		reference = "https://attack.mitre.org/software/S0081/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_elise_pdb.yar#L1-L29"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "b426dbe0f281fe44495c47b35c0fb61b28558b5c8d9418876e22ec3de4df9e7b"
		logic_hash = "bb7eee8082aa0f6634a8c4cdb9cbe0e2a7f00b97e48609c81a21bdaac64a5496"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Elise"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\lstudio\\projects\\lotus\\elise\\Release\\EliseDLL\\i386\\EliseDLL.pdb"
		$pdb1 = "\\LStudio\\Projects\\Lotus\\Elise\\Release\\SetElise.pdb"
		$pdb2 = "\\lstudio\\projects\\lotus\\elise\\Release\\SetElise\\i386\\SetElise.pdb"
		$pdb3 = "\\LStudio\\Projects\\Lotus\\Elise\\Release\\Uninstaller.pdb"
		$pdb4 = "\\lstudio\\projects\\lotus\\evora\\Release\\EvoraDLL\\i386\\EvoraDLL.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <50KB and any of them
}
