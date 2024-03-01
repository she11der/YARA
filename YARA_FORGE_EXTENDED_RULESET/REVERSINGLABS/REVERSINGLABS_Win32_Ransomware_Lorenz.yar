rule REVERSINGLABS_Win32_Ransomware_Lorenz : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Lorenz ransomware."
		author = "ReversingLabs"
		id = "cc97dd15-d518-5d9f-9384-3dcf81e34e81"
		date = "2022-10-24"
		modified = "2022-10-24"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.Lorenz.yara#L1-L252"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b8668fcc560d264c37e3fbb52d5a5f1223a282abd9e984b3109efe9ab454be9f"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "Lorenz"
		tc_detection_factor = 5
		importance = 25

	strings:
		$encrypt_files_v1_p1 = {
            BE ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? A5 6A ?? 6A ?? 68 ?? ?? ?? ?? FF B5 ?? ??
            ?? ?? A5 A5 A4 8B 35 ?? ?? ?? ?? FF D6 89 85 ?? ?? ?? ?? 33 C0 50 68 ?? ?? ?? ?? 6A
            ?? 50 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF D6 68 ?? ?? ?? ?? 6A ?? 6A ?? 89 85
            ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 85 C0 75
            ?? FF D6 8B 3D ?? ?? ?? ?? 6A ?? FF B5 ?? ?? ?? ?? FF D7 EB ?? 8B 3D ?? ?? ?? ?? 8D
            85 ?? ?? ?? ?? 50 6A ?? 6A ?? 68 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85
            C0 75 ?? FF D6 6A ?? FF B5 ?? ?? ?? ?? FF D7 6A ?? 6A ?? 53 FF B5 ?? ?? ?? ?? FF 15
            ?? ?? ?? ?? 85 C0 75 ?? FF D6 8D 85 ?? ?? ?? ?? 33 DB 50 53 FF B5 ?? ?? ?? ?? 68 ??
            ?? ?? ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? FF D6 53 FF B5 ?? ?? ?? ??
            FF D7 6A ?? 8D 45 ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ??
            ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 53 8B 9D ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 8B
            0D ?? ?? ?? ?? 83 A5 ?? ?? ?? ?? ?? 89 4D ?? 66 8B 0D ?? ?? ?? ?? 66 89 4D ?? 8D 4D
            ?? 89 85 ?? ?? ?? ?? 8D 51 ?? 8A 01 41 84 C0 75 ?? 8B B5 ?? ?? ?? ?? 8D 85 ?? ?? ??
            ?? 6A ?? 50 2B CA 8D 45 ?? 51 50 56 FF 15 ?? ?? ?? ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 68
            ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 33 C0 50 50
        }
		$encrypt_files_v1_p2 = {
            50 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 33 D2 42 3B C2 75 ?? 83 BD ?? ?? ?? ?? ??
            0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15
            ?? ?? ?? ?? 33 D2 42 83 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 03 8D
            ?? ?? ?? ?? 3B 8D ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 6A ?? 89 8D ?? ?? ?? ?? 0F 44 C2 8D
            8D ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 51 8D 4D ?? 51 6A ?? 50 6A ?? FF B5 ?? ?? ?? ?? FF
            15 ?? ?? ?? ?? 85 C0 74 ?? 83 A5 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF B5 ??
            ?? ?? ?? 8D 45 ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 6A ?? 8D 45 ?? 6A ?? 50 E8 ??
            ?? ?? ?? 83 C4 ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 8D 45 ?? 50 53 FF 15 ?? ?? ?? ??
            85 C0 0F 85 ?? ?? ?? ?? 6A ?? FF B5 ?? ?? ?? ?? FF D7 FF B5 ?? ?? ?? ?? FF 15 ?? ??
            ?? ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 53 FF D6 8B 85 ?? ?? ??
            ?? 50 FF D6 FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F
            5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C2
        }
		$find_files_v1_p1 = {
            FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 6A ?? 0F 57 C0 C6 45
            ?? ?? 6A ?? 6A ?? 0F 11 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 85 ?? ?? ?? ?? 85
            C0 74 ?? 89 18 89 58 ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 89 08 8B 3D ?? ?? ?? ??
            8B B5 ?? ?? ?? ?? C6 45 ?? ?? F6 85 ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ??
            8D 85 ?? ?? ?? ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ??
            50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF D7 85 C0 0F
            84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 68
            ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85
            ?? ?? ?? ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF
            D7 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF D7 85 C0 0F 84 ??
            ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ??
            ?? ?? 8D 85 ?? ?? ?? ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ??
            ?? ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF D7 85
            C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF D7 85 C0 0F 84 ?? ?? ??
            ?? 8D 85 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 8B F0 C6 45 ?? ?? 8D 8D
        }
		$find_files_v1_p2 = {
            8B 95 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 56 8B D0 C6 45 ?? ?? 8D 4D ?? E8
            ?? ?? ?? ?? 59 50 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ??
            E8 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 75 ?? 68 ?? ?? ??
            ?? 0F 43 75 ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 56 50 89 85 ?? ?? ?? ?? E8 ?? ??
            ?? ?? 8B B5 ?? ?? ?? ?? 83 C4 ?? F6 85 ?? ?? ?? ?? ?? 75 ?? 56 8D 4D ?? E8 ?? ?? ??
            ?? 8D 45 ?? C6 45 ?? ?? 50 E8 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 56 E8
            ?? ?? ?? ?? F6 85 ?? ?? ?? ?? ?? 59 74 ?? 8D 45 ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ??
            ?? 83 7D ?? ?? 8D 75 ?? 68 ?? ?? ?? ?? 0F 43 75 ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ??
            ?? 56 50 89 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ??
            ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 8D 4D ?? E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? C7 45 ?? ??
            ?? ?? ?? EB ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59
            B8 ?? ?? ?? ?? C3 C7 45 ?? ?? ?? ?? ?? 33 DB 8B 85 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 89
            85 ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 0F
            85 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 8D 8D
        }
		$create_scheduled_task_v1 = {
            FF 15 ?? ?? ?? ?? 33 FF 85 C0 74 ?? 8B CF 8A 84 0D ?? ?? ?? ?? 88 84 0D ?? ?? ?? ??
            41 84 C0 75 ?? 8D BD ?? ?? ?? ?? 4F 8A 47 ?? 47 84 C0 75 ?? BE ?? ?? ?? ?? A5 A5 66
            A5 33 FF 57 68 ?? ?? ?? ?? 6A ?? 57 57 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ??
            ?? ?? ?? 8B 4B ?? 8B F0 89 BD ?? ?? ?? ?? 8D 51 ?? 8A 01 41 84 C0 75 ?? 57 8D 85 ??
            ?? ?? ?? 2B CA 50 51 FF 73 ?? 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 68 ?? ?? ??
            ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 83 C4 ?? 8B
            F2 8A 02 42 84 C0 75 ?? 8D BD ?? ?? ?? ?? 2B D6 4F 8A 47 ?? 47 84 C0 75 ?? 8B CA C1
            E9 ?? F3 A5 8B CA 83 E1 ?? F3 A4 8D 8D ?? ?? ?? ?? 49 8A 41 ?? 41 84 C0 75 ?? 66 A1
            ?? ?? ?? ?? 33 DB 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? 66 89 01 A0 ?? ?? ?? ?? 53 53 88
            41 ?? 8D 85 ?? ?? ?? ?? 50 57 53 53 FF D6 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 53 53 68
            ?? ?? ?? ?? 57 53 53 FF D6 8B 4D ?? 5F 5E 33 CD 5B E8 ?? ?? ?? ?? 8B E5 5D C3
        }
		$remote_connection_v1 = {
            55 8B EC 83 E4 ?? 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 53 8B
            5D ?? 8D 44 24 ?? 56 57 8B 7D ?? 50 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? 6A
            ?? 6A ?? 6A ?? 58 50 FF 15 ?? ?? ?? ?? 8B F0 83 FE ?? 74 ?? 6A ?? 58 53 66 89 44 24
            ?? FF 15 ?? ?? ?? ?? FF 75 ?? 89 44 24 ?? FF 15 ?? ?? ?? ?? 66 89 44 24 ?? 8D 44 24
            ?? 6A ?? 50 56 FF 15 ?? ?? ?? ?? 83 F8 ?? 74 ?? 8B CF 8D 51 ?? 8A 01 41 84 C0 75 ??
            6A ?? 2B CA 51 57 56 FF 15 ?? ?? ?? ?? 83 F8 ?? 75 ?? 56 FF 15 ?? ?? ?? ?? FF 15 ??
            ?? ?? ?? 33 C0 8B 8C 24 ?? ?? ?? ?? 5F 5E 5B 33 CC E8 ?? ?? ?? ?? 8B E5 5D C2
        }
		$check_mutex_v1 = {
            E8 ?? ?? ?? ?? 59 59 56 C6 45 ?? ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 85 ??
            ?? ?? ?? 50 FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 E0 ?? 50 FF B5
            ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 7D ?? ?? 7E ?? 8B 57 ?? E8 ?? ?? ?? ?? 50 E8 ?? ??
            ?? ?? 59 FF 77 ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B C8 C6 45 ?? ?? E8 ?? ?? ??
            ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8D 85 ?? ?? ??
            ?? 68 ?? ?? ?? ?? 50 56 FF D3 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ??
            56 FF 15 ?? ?? ?? ?? 8B F8 FF 15 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 94 C0 85 FF 74 ?? 84
            C0 74 ?? 57 FF 15 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 56
        }
		$find_files_v2 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 83 EC ?? 53
            56 57 89 65 ?? 8D 4D ?? C7 45 ?? ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 83 EC ?? C6 45
            ?? ?? 8D 4D ?? 54 E8 ?? ?? ?? ?? 83 EC ?? 8D 4D ?? 54 E8 ?? ?? ?? ?? 83 EC ?? 8D 4D
            ?? 54 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? E8 ??
            ?? ?? ?? 83 EC ?? C7 45 ?? ?? ?? ?? ?? 8D 45 ?? 8D 4D ?? 50 E8 ?? ?? ?? ?? 8D 4D ??
            3B 45 ?? 0F 87 ?? ?? ?? ?? 83 EC ?? C7 45 ?? ?? ?? ?? ?? 8D 45 ?? 50 E8 ?? ?? ?? ??
            51 50 8D 45 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 8B F0 8D 45 ?? 3B C6 74 ?? 8B 45 ?? 83 F8
            ?? 72 ?? 6A ?? 40 50 FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 C7 45 ?? ?? ?? ?? ?? 56
            8D 4D ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B
            7D ?? 33 F6 8B 5D ?? 83 FE ?? 73 ?? 8B 0C B5 ?? ?? ?? ?? 8D 45 ?? 83 FF ?? 0F 43 C3
            66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1
            ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 74 ?? 46 EB ?? 8D 4D ?? E8 ?? ??
            ?? ?? B0 ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C2 ?? ?? 8D 4D ?? E8 ??
            ?? ?? ?? 8B 4D ?? 32 C0 5F 5E 64 89 0D ?? ?? ?? ?? 5B 8B E5 5D C2 ?? ?? 8D 45
        }
		$encrypt_files_v2_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 51 B8 ?? ??
            ?? ?? E8 ?? ?? ?? ?? 53 56 57 C7 45 ?? ?? ?? ?? ?? 8B F1 8B 7D ?? 8D 4D ?? 89 65 ??
            57 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 45 ?? 8B CE 50 E8
            ?? ?? ?? ?? 8B D8 C6 45 ?? ?? 8D 4D ?? 89 5D ?? E8 ?? ?? ?? ?? 8B 75 ?? 56 E8 ?? ??
            ?? ?? 83 C4 ?? 56 53 50 E8 ?? ?? ?? ?? 8B 75 ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56
            50 E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 83 C4 ?? 49 0F 1F 40 ?? 8A 41 ?? 8D 49 ?? 84 C0
            75 ?? A1 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 08 89 ?? ?? ?? ?? 4E 00 6A ?? 6A ?? 89 41 ??
            A1 ?? ?? ?? ?? ?? ?? ?? ?? 08 A0 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 8B 35 ?? ?? ?? ?? 88
            41 ?? FF D6 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 68 ??
            ?? ?? ?? 50 FF D6 68 ?? ?? ?? ?? 6A ?? 6A ?? 89 45 ?? 8D 45 ?? 6A ?? 50 FF 15 ?? ??
            ?? ?? 8B 35 ?? ?? ?? ?? 85 C0 75 ?? FF D6 8B 1D ?? ?? ?? ?? 6A ?? FF 75 ?? FF D3 EB
            ?? 8B 1D ?? ?? ?? ?? 8D 45 ?? 50 6A ?? 6A ?? 68 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ??
            ?? 85 C0 75 ?? FF D6 6A ?? FF 75 ?? FF D3 6A ?? 6A ?? 57 FF 75 ?? FF 15 ?? ?? ?? ??
            85 C0 75 ?? FF D6 8D 45 ?? 50 6A ?? FF 75 ?? 68 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ??
            ?? 85 C0 75 ?? FF D6 6A ?? FF 75 ?? FF D3 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50
        }
		$encrypt_files_v2_p2 = {
            E8 ?? ?? ?? ?? 8B 7D ?? 83 C4 ?? 33 F6 C7 45 ?? ?? ?? ?? ?? 33 DB 89 5D ?? 56 57 FF
            15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 89 4D ?? 66 8B 0D ?? ?? 4E 00 66 89 4D ?? 8D 4D ??
            89 45 ?? 8D 51 ?? 89 5D ?? 8A 01 41 84 C0 75 ?? 6A ?? 8D 45 ?? 2B CA 50 51 8D 45 ??
            50 FF 75 ?? FF 15 ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 68 ?? ?? ?? ?? FF 75 ?? FF 75 ?? FF
            15 ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 57 FF 15 ?? ??
            ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 66 0F 1F 44 00 ?? 8B 45 ?? 85 C0 0F 84 ?? ?? ?? ?? 03
            F0 33 C9 3B 75 ?? 75 ?? 85 C9 75 ?? 33 DB 83 F8 ?? 0F 95 C3 68 ?? ?? ?? ?? 8D 45 ??
            50 8D 85 ?? ?? ?? ?? 50 6A ?? 53 6A ?? FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 6A ??
            8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 FF 75 ?? 8D 85 ?? ?? ?? ?? 50 FF 75 ?? FF 15 ?? ??
            ?? ?? 85 C0 74 ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ??
            8D 45 ?? 6A ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 0F
            85 ?? ?? ?? ?? 6A ?? FF 75 ?? FF 15 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? FF 75 ??
            FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 57 FF D6 FF 75 ?? FF D6 8B 4D ?? 5F 5E 64 89 0D
            ?? ?? ?? ?? 5B 8B E5 5D C2 ?? ?? 8D 45
        }
		$remote_connection_v2 = {
            55 8B EC 51 53 56 57 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? FF
            15 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B F0 68 ?? ?? ?? ?? 56
            FF 15 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B D8 6A ??
            53 FF 15 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8B F8 6A ?? 57 FF 15 ?? ?? ?? ?? 6A ?? 6A ??
            8D 45 ?? 50 57 FF 15 ?? ?? ?? ?? 56 8B 35 ?? ?? ?? ?? FF D6 53 FF D6 57 FF D6 5F 5E
            33 C0 5B 8B E5 5D C3
        }
		$drop_ransom_note_v2_p1 = {
            6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 89 45 ??
            C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 6A ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7
            45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 85 C0 74 ?? C7 00 ?? ?? ?? ?? C7
            40 ?? ?? ?? ?? ?? 8B 45 ?? 8D 4D ?? 89 08 68 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45
            ?? ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ?? 68 ?? ?? ?? ??
            68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? ?? ?? ?? ?? 87 FB 00 00 00 A0 ?? ??
            ?? ?? 88 87 ?? ?? ?? ?? 8B F7 8D 4E ?? 0F 1F 40 ?? 8A 06 46 84 C0 75 ?? 2B F1 8D 46
            ?? 50 E8 ?? ?? ?? ?? 8B D8 83 C4 ?? 85 DB 74 ?? 56 57 53 E8 ?? ?? ?? ?? 6A ?? 8D 04
            33 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B F3 8D 4E ?? 0F 1F 44 00 ?? 8A 06 46
            84 C0 75 ?? 2B F1 8D 86 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ?? 56
            53 57 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 04 37 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4
            ?? 8B F7 8D 4E ?? 8A 06 46 84 C0 75 ?? 2B F1 8D 86 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B
            D8 83 C4 ?? 85 DB 74 ?? 56 57 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 04 33 68 ?? ?? ??
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B F3 8D 4E ?? 8A 06 46 84 C0 75 ?? 2B F1 8D 46 ?? 50
        }
		$drop_ransom_note_v2_p2 = {
            E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ?? 56 53 57 E8 ?? ?? ?? ?? 6A ?? 8D 04 37 68
            ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B F7 8D 4E ?? 0F 1F 00 8A 06 46 84 C0 75 ??
            2B F1 8D 46 ?? 50 E8 ?? ?? ?? ?? 8B D8 83 C4 ?? 85 DB 74 ?? 56 57 53 E8 ?? ?? ?? ??
            F3 0F 7E 05 ?? ?? ?? ?? 83 C4 ?? 66 0F D6 04 33 8B F3 8D 4E ?? 8A 06 46 84 C0 75 ??
            2B F1 8D 46 ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ?? 56 53 57 E8 ?? ?? ?? ??
            6A ?? 8D 04 37 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B F7 8D 4E ?? 8A 06 46 84
            C0 75 ?? 2B F1 8D 46 ?? 50 E8 ?? ?? ?? ?? 8B D8 83 C4 ?? 85 DB 74 ?? 56 57 53 E8 ??
            ?? ?? ?? 6A ?? 8D 04 33 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B F3 8D 4E ?? 66
            90 8A 06 46 84 C0 75 ?? 2B F1 8D 46 ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ??
            56 53 57 E8 ?? ?? ?? ?? 6A ?? 8D 04 37 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B
            CF 5B 8D 51 ?? 0F 1F 40 ?? 8A 01 41 84 C0 75 ?? 8B 75 ?? 8D 45 ?? 6A ?? 50 2B CA 51
            57 56 FF 15 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 56 FF 15 ?? ?? ?? ?? 8D 4D
            ?? E8 ?? ?? ?? ?? 8B 4D ?? 5F 5E 64 89 0D ?? ?? ?? ?? 8B E5 5D C2
        }

	condition:
		uint16(0)==0x5A4D and ((( all of ($encrypt_files_v1_p*)) and ( all of ($find_files_v1_p*)) and ($create_scheduled_task_v1) and ($remote_connection_v1) and ($check_mutex_v1)) or (($find_files_v2) and ( all of ($encrypt_files_v2_p*)) and ($remote_connection_v2) and ( all of ($drop_ransom_note_v2_p*))))
}