rule REVERSINGLABS_Win32_Ransomware_Ophionlocker : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects OphionLocker ransomware."
		author = "ReversingLabs"
		id = "75335749-66bd-539e-92b3-dd92c0b332d8"
		date = "2020-07-15"
		modified = "2020-07-15"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.OphionLocker.yara#L1-L105"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3c54a948a6a45ec5f5bc32fbbdbc8822f402b1332e9109b20b90635464dbe2ac"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "OphionLocker"
		tc_detection_factor = 5
		importance = 25

	strings:
		$ol_do_filetypes_1 = {
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 53 56 57 33 DB 53 89 5D ?? 53 89 5D ?? 89 5D ?? E8 ?? ?? ?? ?? 89 45 ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
        }
		$ol_do_filetypes_2 = {
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
            C6 45 ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 85 ?? ?? ?? ?? FF 75 ?? 8D 4D ?? 89 5D ?? 50
            8D 85 ?? ?? ?? ?? 89 5D ?? 50 53 89 5D ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 E8
            ?? ?? ?? ?? 83 EC ?? 8D 45 ?? 8B CC 89 65 ?? 50 E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8D 45 ?? 8B CC 8D 75 ?? 50 E8 ?? ??
            ?? ?? 8B CE C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 58 89 45 ?? 89 5D ?? 88 5D ?? 89 45 ?? 89
            5D ?? 88 5D ?? 83 C4 ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8B 4D ?? 8B 39 E9 00 01 00 00 8B 77 ??
            8D 47 ?? 89 45 ?? 3B 77 ?? 0F 84 EC 00 00 00 8B F8 68 ?? ?? ?? ?? 8B D7 8D 4D ?? E8 ?? ?? ?? ?? 56 8B D0 C6 45 ?? ?? 8D
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 59 50 8D 4D ?? E8 ?? ?? ?? ?? 53 6A ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 6A ?? 8D 4D
        }
		$ol_do_filetypes_3 = {
            ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8B CC 89 65 ?? 50 E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? ??
            89 65 ?? 8D 45 ?? 83 EC ?? 8B CC 50 E8 ?? ?? ?? ?? 8B 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ??
            81 C4 ?? ?? ?? ?? 8D 4D ?? 50 E8 ?? ?? ?? ?? 53 6A ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 EC ?? 8D 45 ?? 8B CC 89 65 ?? 50 E8 ??
            ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8D 45 ?? 8B CC 50 E8 ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 C6 ?? 83 C4 ?? 3B 77 ?? 0F
            85 1C FF FF FF 8B 4D ?? 8B 7D ?? 8B 3F 89 7D ?? 3B F9 0F 85 F5 FE FF FF 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? C6 45
            ?? ?? 8D 85 ?? ?? ?? ?? 89 65 ?? 8B CC BA ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8B CC E8 ?? ?? ?? ?? C6 45
            ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 8B CC 89 65 ?? BA ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8B
            CC E8 ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 53 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 33 F6 8D 8D
            ?? ?? ?? ?? 53 46 56 E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ??
            ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 53 56 8D 4D ?? E8 ?? ?? ?? ?? 53 56 8D 4D ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ??
            E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 53 56 8D 4D ?? E8 ?? ??
            ?? ?? 8B 4D ?? 5F 5E 64 89 0D ?? ?? ?? ?? 5B 8B E5 5D C3
        }
		$ol_ecies_key_1 = {
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 53 56 57 8B F9 33 DB 89 5D ?? 8D 8D ?? ?? ?? ?? 89 7D ?? 89 5D ?? E8 ??
            ?? ?? ?? 33 F6 8D 85 ?? ?? ?? ?? 46 8D 8D ?? ?? ?? ?? 50 BA ?? ?? ?? ?? 89 75 ?? E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8B
            CC 8B D0 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8D 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? 53 56 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ??
            ?? ?? BE ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 59 50 56 FF 75 ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 85 C0 0F 85 40 03 00 00 8D 8D ?? ??
            ?? ?? E8 ?? ?? ?? ?? 50 51 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 51
            8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ??
            ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? 8B B4 05 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? FF 50 ?? 50 8B 85 ??
            ?? ?? ?? 8D 8D ?? ?? ?? ?? 8B 40 ?? 03 C8 FF 56 ?? 68 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 8D
            ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? FF 50 ?? 8D 55 ?? 8B C8 E8 ?? ?? ?? ?? 53 6A ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? BB ??
            ?? ?? ?? 8D 4D ?? 53 E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? FF 50 ?? 83 7D ?? ?? 8D 4D ?? 8B F0
            0F 43 4D ?? 51 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 95 ?? ?? ?? ?? 8B 06 52 8B 48 ?? 03 CE 8B 01 FF 50 ??
            C6 45 ?? ?? 8B 8D ?? ?? ?? ?? 85 C9 74 0D 8B 01 6A ?? 8B 40 ?? 03 C8 8B 01 FF 10 33 F6 C6 45 ?? ?? 56 6A ?? 8D 4D ?? E8
            ?? ?? ?? ?? 83 EC ?? 8B CC 53 E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B D0 C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ??
        }
		$ol_ecies_key_2 = {
            56 6A ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 8B CC 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ??
            ?? 83 C4 ?? 8B D0 C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 6A ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 53
            E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45
            ?? ?? 50 8D 55 ?? 8D 4D ?? E8 ?? ?? ?? ?? 59 50 8D 4D ?? E8 ?? ?? ?? ?? 56 6A ?? 8D 4D ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ??
            56 E8 ?? ?? ?? ?? 59 50 56 8D 4D ?? E8 ?? ?? ?? ?? 6A ?? 6A ?? 8D 45 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 56 E8
            ?? ?? ?? ?? 59 50 56 8D 4D ?? E8 ?? ?? ?? ?? 6A ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 56
            E8 ?? ?? ?? ?? 59 50 56 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 6A ?? 33 F6 C6 45 ?? ?? 56 50 8D 4D ?? E8 ?? ??
            ?? ?? 56 6A ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 8D 45 ?? 8B CC BA ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 8D 8D ??
            ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 95 ?? ?? ?? ?? 8B CC 89 65 ?? E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8B CC 53 E8 ??
            ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? 56 6A ?? E8 ?? ?? ?? ?? 56 6A ?? 8D 4D ?? E8 ?? ?? ?? ??
            56 6A ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 6A ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ??
        }
		$ol_ecies_key_3 = {
            8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? EB 30 83 EC ?? 8D 55 ?? 8B CC 89 65 ?? E8
            ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8B CC BB ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 51 8D 4F ??
            E8 ?? ?? ?? ?? 8D 77 ?? C7 07 ?? ?? ?? ?? C7 06 ?? ?? ?? ?? C7 47 ?? ?? ?? ?? ?? 53 8D 4D ?? C7 45 ?? ?? ?? ?? ?? E8 ??
            ?? ?? ?? 8D 46 ?? C6 45 ?? ?? 85 C0 74 05 8D 4E ?? EB 02 33 C9 8D 55 ?? E8 ?? ?? ?? ?? 6A ?? 6A ?? 8D 4D ?? C6 45 ?? ??
            E8 ?? ?? ?? ?? 8B 06 8B CE FF 50 ?? 6A ?? 68 ?? ?? ?? ?? 8B 08 8B 49 ?? 03 C8 8B 01 FF 50 ?? 53 E8 ?? ?? ?? ?? 59 6A ??
            6A ?? 8D 4D ?? E8 ?? ?? ?? ?? 6A ?? 6A ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D ?? 8B C7 5F 5E 64 89 0D ?? ?? ?? ?? 5B
            8B E5 5D C3
        }

	condition:
		uint16(0)==0x5A4D and (($ol_do_filetypes_1 and $ol_do_filetypes_2 and $ol_do_filetypes_3) and ($ol_ecies_key_1 and $ol_ecies_key_2 and $ol_ecies_key_3))
}
