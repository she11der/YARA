rule REVERSINGLABS_Win32_Infostealer_Stealc : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects StealC infostealer."
		author = "ReversingLabs"
		id = "b53bbf15-3e94-513c-91a9-83dda421063b"
		date = "2023-06-07"
		modified = "2023-06-07"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/infostealer/Win32.Infostealer.StealC.yara#L1-L57"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bea1cf370150387eb185deff726e10e660e7eb571c20d22878def08b36f457bf"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Infostealer"
		tc_detection_name = "StealC"
		tc_detection_factor = 5
		importance = 25

	strings:
		$resolve_windows_api = {
            55 8B EC 51 83 65 ?? ?? 56 64 A1 ?? ?? ?? ?? 8B 40 ?? 8B 40 ?? 8B 00 8B 00 8B 40 ??
            89 45 ?? 8B 75 ?? 89 35 ?? ?? ?? ?? 85 F6 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ??
            ?? ?? ?? A3 ?? ?? ?? ?? 56 FF D0 FF 35 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 35
        }
		$load_sqlite3_functions = {
            55 8B EC 83 EC ?? 6A ?? FF 15 ?? ?? ?? ?? 8B 4D ?? 50 89 45 ?? 89 4D ?? 8B 4D ?? 8D
            45 ?? 50 89 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 8D 45 ?? 57 89 45 ?? 8B 7D ??
            B9 ?? ?? ?? ?? 33 C0 F3 AA 5F 33 C0 C9 C3 8B 45 ?? 85 C0 74 ?? 53 8B 58 ?? 56 8B 70
            ?? FF 35 ?? ?? ?? ?? 8B C6 E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B C6 E8
            ?? ?? ?? ?? FF 35 ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B C6 E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ??
            A3 ?? ?? ?? ?? 8B C6 E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B C6 E8 ?? ??
            ?? ?? FF 35 ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B C6 E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? A3
        }
		$check_license_expiration_date = {
            55 8B EC 83 E4 ?? 83 EC ?? 57 33 C0 66 89 44 24 ?? 83 64 24 ?? ?? 8D 7C 24 ?? AB AB
            AB 66 AB 33 C0 66 89 44 24 ?? 8D 7C 24 ?? AB AB AB 66 AB 33 C0 21 44 24 ?? 8D 7C 24
            ?? AB 8D 7C 24 ?? AB 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 8D 7C 24 ?? E8 ?? ?? ?? ?? 8D
            4C 24 ?? 51 8D 4C 24 ?? 51 8D 4C 24 ?? 51 FF 35 ?? ?? ?? ?? FF 30 FF 15 ?? ?? ?? ??
            8B 44 24 ?? 83 C4 ?? E8 ?? ?? ?? ?? 8D 44 24 ?? 50 8D 44 24 ?? 50 FF 15 ?? ?? ?? ??
            8D 44 24 ?? 50 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 8B 44 24 ?? 3B 44 24 ?? 72 ?? 77 ??
            8B 44 24 ?? 3B 44 24 ?? 76 ?? 6A ?? FF 15 ?? ?? ?? ?? 5F 8B E5 5D C3
        }

	condition:
		uint16(0)==0x5A4D and ($resolve_windows_api) and ($load_sqlite3_functions) and ($check_license_expiration_date)
}
