rule FIREEYE_RT_Credtheft_Win_EXCAVATOR_1 : FILE
{
	meta:
		description = "This rule looks for the binary signature of the 'Inject' method found in the main Excavator PE."
		author = "FireEye"
		id = "7cabc230-e55b-5096-996a-b6a8c9693bdc"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/EXCAVATOR/production/yara/CredTheft_Win_EXCAVATOR_1.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "f7d9961463b5110a3d70ee2e97842ed3"
		logic_hash = "bf4b776f34a1a9aa5438504f63a63ef452a747363de3b70cec52145d777055bd"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 4

	strings:
		$bytes1 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 20 01 00 00 48 8B 05 75 BF 01 00 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 8D 0D 12 A1 01 00 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 00 FF 15 CB 1F 01 00 48 85 C0 75 1B FF 15 80 1F 01 00 8B D0 48 8D 0D DF A0 01 00 E8 1A FF FF FF 33 C0 E9 B4 02 00 00 48 8D 15 D4 A0 01 00 48 89 9C 24 30 01 00 00 48 8B C8 FF 15 4B 1F 01 00 48 8B D8 48 85 C0 75 19 FF 15 45 1F 01 00 8B D0 48 8D 0D A4 A0 01 00 E8 DF FE FF FF E9 71 02 00 00 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 45 66 66 0F 1F 84 00 00 00 00 00 48 8B 4C 24 60 FF 15 4D 1F 01 00 3B C6 74 22 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 D1 EB 0A 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A0 01 00 48 8D 05 A6 C8 01 00 B9 C8 05 00 00 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 B2 FF 15 CC 1E 01 00 4C 8D 44 24 78 BA 0A 00 00 00 48 8B C8 FF 15 01 1E 01 00 85 C0 0F 84 66 01 00 00 48 8B 4C 24 78 48 8D 45 80 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 D8 1D 01 00 85 C0 0F 84 35 01 00 00 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 50 01 FF 15 5C 1E 01 00 FF 15 06 1E 01 00 4C 8B 44 24 68 33 D2 48 8B C8 FF 15 DE 1D 01 00 48 8B F8 48 85 C0 0F 84 FF 00 00 00 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 50 01 FF 15 25 1E 01 00 85 C0 0F 84 E2 00 00 00 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 6C 1D 01 00 85 C0 0F 84 B1 00 00 00 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C 8D 05 58 39 03 00 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 44 24 30 04 00 08 00 44 89 74 24 28 4C 89 74 24 20 FF 15 0C 1D 01 00 85 C0 74 65 48 8B 4C 24 70 8B 5D 98 FF 15 1A 1D 01 00 48 8B 4D 88 FF 15 10 1D 01 00 48 8B 4D 90 FF 15 06 1D 01 00 44 8B C3 33 D2 B9 3A 04 00 00 FF 15 4E 1D 01 00 48 8B D8 48 85 C0 74 2B 48 8B C8 E8 4E 06 00 00 48 85 C0 74 1E BA FF FF FF FF 48 8B C8 FF 15 3B 1D 01 00 48 8B CB FF 15 CA 1C 01 00 B8 01 00 00 00 EB 24 FF 15 DD 1C 01 00 8B D0 48 8D 0D 58 9E 01 00 E8 77 FC FF FF 48 85 FF 74 09 48 8B CF FF 15 A9 1C 01 00 33 C0 48 8B 9C 24 30 01 00 00 48 8B 4D 10 48 33 CC E8 03 07 00 00 4C 8D 9C 24 20 01 00 00 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
		$bytes2 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 2? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 ?? FF ?? ?? ?? ?? ?? 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 9C 24 3? ?1 ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 66 0F 1F 84 ?? ?? ?? ?? ?? 48 8B 4C 24 60 FF ?? ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A? ?1 ?? 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 ?? FF ?? ?? ?? ?? ?? 4C 8D 44 24 78 BA 0A ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 78 48 8D 45 80 41 B9 02 ?? ?? ?? 48 89 44 24 28 45 33 C0 C7 44 24 2? ?2 ?? ?? ?? 41 8D 51 09 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 5? ?1 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 4C 8B 44 24 68 33 D2 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 5? ?1 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 ?? ?? ?? ?? ?? 48 C7 44 24 2? ?8 ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C ?? ?? ?? ?? ?? ?? 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 ?? ?? ?? ?? ?? ?? ?? 44 89 74 24 28 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 70 8B 5D 98 FF ?? ?? ?? ?? ?? 48 8B 4D 88 FF ?? ?? ?? ?? ?? 48 8B 4D 90 FF ?? ?? ?? ?? ?? 44 8B C3 33 D2 B9 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? EB ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF ?? ?? ?? ?? ?? 33 C0 48 8B 9C 24 3? ?1 ?? ?? 48 8B 4D 10 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 2? ?1 ?? ?? 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
		$bytes3 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 2? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 ?? FF ?? ?? ?? ?? ?? 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 9C 24 3? ?1 ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 66 0F 1F 84 ?? ?? ?? ?? ?? 48 8B 4C 24 60 FF ?? ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A? ?1 ?? 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 ?? FF ?? ?? ?? ?? ?? 4C 8D 44 24 78 BA 0A ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 78 48 8D 45 80 41 B9 02 ?? ?? ?? 48 89 44 24 28 45 33 C0 C7 44 24 2? ?2 ?? ?? ?? 41 8D 51 09 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 5? ?1 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 4C 8B 44 24 68 33 D2 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 5? ?1 FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 ?? ?? ?? ?? ?? 48 C7 44 24 2? ?8 ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C ?? ?? ?? ?? ?? ?? 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 ?? ?? ?? ?? ?? ?? ?? 44 89 74 24 28 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 70 8B 5D 98 FF ?? ?? ?? ?? ?? 48 8B 4D 88 FF ?? ?? ?? ?? ?? 48 8B 4D 90 FF ?? ?? ?? ?? ?? 44 8B C3 33 D2 B9 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? EB ?? FF ?? ?? ?? ?? ?? 8B D0 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF ?? ?? ?? ?? ?? 33 C0 48 8B 9C 24 3? ?1 ?? ?? 48 8B 4D 10 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 2? ?1 ?? ?? 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }
		$bytes4 = { 48 89 74 24 ?? 48 89 7C 24 ?? 4C 89 74 24 ?? 55 48 8D 6C 24 ?? 48 81 EC 20 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 ?? 48 8D 0D ?? ?? ?? ?? 4C 89 74 24 ?? 0F 11 45 ?? 41 8B FE 4C 89 74 24 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? 0F 11 45 ?? FF 15 ?? ?? ?? ?? 48 85 C0 75 ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 ?? 66 66 0F 1F 84 00 ?? ?? 00 00 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 3B C6 74 ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 ?? EB ?? 48 8B 44 24 ?? 48 89 44 24 ?? 66 0F 6F 15 ?? ?? 01 00 48 8D 05 ?? ?? ?? ?? B9 C8 05 00 00 90 F3 0F 6F 40 ?? 48 8D 40 ?? 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 ?? 66 0F 6F CA F3 0F 6F 40 ?? 66 0F EF C8 F3 0F 7F 48 ?? 66 0F 6F CA F3 0F 6F 40 ?? 66 0F EF C8 F3 0F 7F 48 ?? F3 0F 6F 40 ?? 66 0F EF C2 F3 0F 7F 40 ?? 48 83 E9 01 75 ?? FF 15 ?? ?? ?? ?? 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 45 ?? 41 B9 02 00 00 00 48 89 44 24 ?? 45 33 C0 C7 44 24 ?? 02 00 00 00 41 8D 51 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 4C 8B 44 24 ?? 33 D2 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 4C 8D 4C 24 ?? 48 8B C8 41 8D 50 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 4C 89 74 24 ?? 4C 8D 4C 24 ?? 4C 89 74 24 ?? 33 D2 41 B8 00 00 02 00 48 C7 44 24 ?? 08 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D ?? 48 8D 45 ?? 48 89 44 24 ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 45 ?? 48 89 7D ?? 48 89 44 24 ?? 45 33 C9 4C 89 74 24 ?? 33 D2 4C 89 74 24 ?? C7 44 24 ?? 04 00 08 00 44 89 74 24 ?? 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 8B 5D ?? FF 15 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 44 8B C3 33 D2 B9 3A 04 00 00 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 74 ?? BA FF FF FF FF 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 FF 74 ?? 48 8B CF FF 15 ?? ?? ?? ?? 33 C0 48 8B 9C 24 ?? ?? ?? ?? 48 8B 4D ?? 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 ?? ?? ?? ?? 49 8B 73 ?? 49 8B 7B ?? 4D 8B 73 ?? 49 8B E3 5D C3 }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and any of ($bytes*)
}
