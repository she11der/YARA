rule FIREEYE_RT_APT_Loader_Win_PGF_1___FILE
{
	meta:
		description = "PDB string used in some PGF DLL samples"
		author = "FireEye"
		id = "fcbefa45-8dcd-57a3-a2ac-f4613152716f"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/PGF/production/yara/APT_Loader_Win_PGF_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "013c7708f1343d684e3571453261b586"
		logic_hash = "a0c51ff1e029072dfccb13f6237b554502775a57dce132aacb1cf20b1c4410a0"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 6

	strings:
		$pdb1 = /RSDS[\x00-\xFF]{20}c:\\source\\dllconfig-master\\dllsource[\x00-\xFF]{0,500}\.pdb\x00/ nocase
		$pdb2 = /RSDS[\x00-\xFF]{20}C:\\Users\\Developer\\Source[\x00-\xFF]{0,500}\Release\\DllSource\.pdb\x00/ nocase
		$pdb3 = /RSDS[\x00-\xFF]{20}q:\\objchk_win7_amd64\\amd64\\init\.pdb\x00/ nocase

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and filesize <15MB and any of them
}