rule REVERSINGLABS_Win32_Ransomware_Satana : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Satana ransomware."
		author = "ReversingLabs"
		id = "8dc5bf7c-d4cb-5961-804b-035676dacbc0"
		date = "2020-07-15"
		modified = "2020-07-15"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.Satana.yara#L1-L123"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5deb6ac2e8b64fb6f7af8c41a9b9e695668ca66c96c65f0c7350b11cd4ae0c50"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "Satana"
		tc_detection_factor = 5
		importance = 25

	strings:
		$encrypt_files_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? 
            ?? 83 EC ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 57 89 65 ?? C7 45 ?? ?? ?? ?? ?? 66 
            0F 57 C0 66 0F 13 45 ?? 68 ?? ?? ?? ?? 8B 75 ?? 56 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 90 
            6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 8B F8 89 
            7D ?? 83 FF ?? 0F 84 ?? ?? ?? ?? 8D 45 ?? 50 57 FF 15 ?? ?? ?? ?? 8B 75 ?? 89 75 ?? 
            8B 5D ?? 89 5D ?? 83 FE ?? 75 ?? 85 DB 0F 84 ?? ?? ?? ?? 8B CE 0B CB 0F 84 ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 6A ?? 53 56 E8 ?? ?? ?? ?? 89 45 ?? 85 C0 74 ?? 33 C9 
            03 C6 13 CB 83 E8 ?? 89 45 ?? 83 D9 ?? 89 4D ?? 6A ?? 8B 55 ?? 52 6A ?? 6A ?? 6A ?? 
            57 FF 15 ?? ?? ?? ?? 89 45 ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? 
            ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 89 45 ?? 8B 4D ?? 89 4D ?? 6A ?? FF 15 ?? 
            ?? ?? ?? 83 C4 ?? 8B F0 66 0F 57 C0 66 0F 13 45 ?? 8B 5D ?? 8B 7D ?? 90 83 7D ?? ?? 
            0F 8C ?? ?? ?? ?? 7F ?? 83 7D ?? ?? 0F 86 ?? ?? ?? ?? 8B D3 83 C2 ?? 8B 75 ?? 8B CE 
            83 D1 ?? 8B 45 ?? 3B C8 7F ?? 7C ?? 3B 55 ?? 77 ?? BF ?? ?? ?? ?? 33 C0 8B 75 ?? 03
        }
		$encrypt_files_p2 = {
            F3 8B DA 89 4D ?? EB ?? 8B 7D ?? 2B FB 1B C6 8B 55 ?? 8D 34 13 03 DF 11 45 ?? 89 5D 
            ?? 89 45 ?? 89 7D ?? 83 7D ?? ?? 7F ?? 7C ?? 83 7D ?? ?? 73 ?? 8B 4D ?? 89 4D ?? 83 
            F9 ?? 7D ?? C6 04 31 ?? 41 EB ?? 29 7D ?? 19 45 ?? 33 C0 89 45 ?? 83 F8 ?? 7D ?? 8B 
            0C 85 ?? ?? ?? ?? 31 0C 86 40 EB ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 45 ?? 85 C0 74 
            ?? 88 04 37 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 01 
            0D ?? ?? ?? ?? 8B 55 ?? 11 15 ?? ?? ?? ?? 8B 45 ?? 50 8B 0D ?? ?? ?? ?? 51 68 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 7D ?? EB ?? 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 FF 
            15 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? EB ?? FF 15 ?? ?? ?? ?? 50 
            68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 57 FF 15 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 8B 
            4D ?? 8D 95 ?? ?? ?? ?? 0F B7 01 66 89 02 83 C1 ?? 83 C2 ?? 66 85 C0 75 ?? 6A ?? 8D 
            95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 83 C4 ?? 83 C0 ?? 74 ?? 8B D0 8D B5 ?? ?? ?? ?? 
            0F B7 0A 66 89 0E 83 C2 ?? 83 C6 ?? 66 85 C9 75 ?? 33 C9 66 89 08 8D 95 ?? ?? ?? ?? 
            52 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 51 FF 15 ?? 
            ?? ?? ?? 83 C4 ?? 8D 95 ?? ?? ?? ?? 52 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 51 FF 
            15 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? 
            ?? ?? EB ?? B8 ?? ?? ?? ?? C3 8B 65 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8
        }
		$search_files_p1 = {
            E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 33 D2 56 50 66 89 94 24 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 33 C9 56 52 
            66 89 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 56 50 89 
            74 24 ?? E8 ?? ?? ?? ?? 8B 7D ?? 83 C4 ?? 8D 4C 24 ?? 51 8D 94 24 ?? ?? ?? ?? 52 68 
            ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? 
            ?? ?? 8D 94 24 ?? ?? ?? ?? 8B C7 2B D7 8D 9B ?? ?? ?? ?? 0F B7 08 66 89 0C 02 83 C0 
            ?? 66 3B CE 75 ?? 8D 84 24 ?? ?? ?? ?? 83 C0 ?? 8D A4 24 ?? ?? ?? ?? 66 8B 48 ?? 83 
            C0 ?? 66 3B CE 75 ?? 8B 0D ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 89 08 66 8B 0D ?? ?? ?? ?? 
            89 50 ?? 68 ?? ?? ?? ?? 66 89 48 ?? FF 15 ?? ?? ?? ?? 8D 54 24 ?? 52 8D 84 24 ?? ?? 
            ?? ?? 50 C7 44 24 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 44 24 ?? 83 F8 ?? 75 ?? 68 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 5F 5E 5B 8B E5 
            5D C2 ?? ?? 8D A4 24 ?? ?? ?? ?? 8B 7D ?? 8B 35 ?? ?? ?? ?? 6A ?? 8D 4C 24 ?? 68 ?? 
            ?? ?? ?? 51 FF D6 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 8D 54 24 ?? 68 ?? ?? ?? ?? 
            52 FF D6 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? F6 44 24 ?? ?? 0F 85 ?? ?? ?? ?? 8D 44 24 
            ?? 6A ?? 50 FF 15 ?? ?? ?? ?? 8B D8 83 C4 ?? 85 DB 0F 84 ?? ?? ?? ?? 66 83 3D ?? ?? 
            ?? ?? ?? BF ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B C7 8D 50 ?? EB ?? 8D 9B ?? ?? ?? ?? 66 
            8B 08 83 C0 ?? 66 85 C9 75 ?? 2B C2 8B CB D1 F8 8D 71 ?? 66 8B 11 83 C1 ?? 66 85 D2
        }
		$search_files_p2 = {
            75 ?? 2B CE D1 F9 3B C1 75 ?? 53 57 FF 15 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 66 8B 0F 
            83 C7 ?? 66 85 C9 75 ?? 66 39 0F 75 ?? E9 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? 
            ?? 64 8B 15 ?? ?? ?? ?? 8B 32 8B 55 ?? 83 C4 ?? 8D 4C 24 ?? 51 52 68 ?? ?? ?? ?? 50 
            89 46 ?? FF 15 ?? ?? ?? ?? 8B 46 ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 C4 ?? 85 
            C0 0F 85 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 F8 ?? 7D ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 
            8B 4E ?? 6A ?? 6A ?? 51 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B 15 ?? ?? ?? 
            ?? 89 04 95 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 0C 85 ?? ?? ?? ?? 6A ?? 51 FF 15 ?? ?? ?? 
            ?? E9 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 
            D3 8B F8 6A ?? 57 FF 15 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? 
            ?? ?? 8B 56 ?? 6A ?? 6A ?? 52 68 ?? ?? ?? ?? 6A ?? 6A ?? FF D3 8B 0D ?? ?? ?? ?? 89 
            04 8D ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 8B 04 95 ?? ?? ?? ?? 6A ?? 50 FF 15 ?? ?? ?? ?? 
            E9 ?? ?? ?? ?? 8D 4C 24 ?? 51 57 8D 94 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 FF 15 ?? ?? 
            ?? ?? A1 ?? ?? ?? ?? 48 50 8D 8C 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 FF D6 83 C4 ?? 85 
            C0 0F 84 ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 83 C4 
            ?? 85 C0 75 ?? 8D 9B ?? ?? ?? ?? 0F B7 8C 04 ?? ?? ?? ?? 66 89 8C 04 ?? ?? ?? ?? 83 
            C0 ?? 66 85 C9 75 ?? 8D BC 24 ?? ?? ?? ?? 83 C7 ?? 66 8B 47 ?? 83 C7 ?? 66 85 C0 75 
            ?? 6A ?? 8D 84 24 ?? ?? ?? ?? 50 B9 ?? ?? ?? ?? BE ?? ?? ?? ?? 68 ?? ?? ?? ?? F3 A5 
            FF 15 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 8B 44 24 ?? 8D 54 24 ?? 52 
            50 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 74 24 ?? 56 FF 15
      }
		$remote_connection = {
            55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 57 E8 ?? ?? ?? ?? 8B D8 85 DB 0F 84 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8B 45 ?? 8B 0D ?? ?? ?? ?? 0F B6 15 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8B 3D ?? 
            ?? ?? ?? 8D 70 ?? 8B 00 56 68 ?? ?? ?? ?? 51 8B 0D ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 52 0F B7 15 ?? ?? ?? ?? 51 8B 0D ?? ?? ?? ?? 52 8B 15 ?? ?? ?? ?? 51 52 50 
            6A ?? 8D 8D ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 FF D7 83 C4 ?? 80 3E ?? 74 ?? B9 ?? ?? ?? 
            ?? 8B C6 EB ?? 8D 49 ?? C6 00 ?? 40 49 75 ?? 8D 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 
            8D 85 ?? ?? ?? ?? 8D 50 ?? 8D 49 ?? 8A 08 40 84 C9 75 ?? 8D 8D ?? ?? ?? ?? 51 2B C2 
            50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 FF D7 8D 85 ?? 
            ?? ?? ?? 83 C4 ?? 8D 50 ?? 8A 08 40 84 C9 75 ?? 6A ?? 2B C2 50 8D 85 ?? ?? ?? ?? 50 
            53 FF 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 9B ?? ?? ?? ?? C6 00 ?? 40 
            49 75 ?? 53 FF 15 ?? ?? ?? ?? 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C2
      }

	condition:
		uint16(0)==0x5A4D and ($remote_connection and ( all of ($search_files_p*)) and ( all of ($encrypt_files_p*)))
}
