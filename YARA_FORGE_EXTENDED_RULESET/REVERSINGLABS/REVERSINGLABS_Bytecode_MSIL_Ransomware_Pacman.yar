rule REVERSINGLABS_Bytecode_MSIL_Ransomware_Pacman : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Pacman ransomware."
		author = "ReversingLabs"
		id = "a440769b-030b-5b72-a6f2-cf478dd7acd2"
		date = "2021-08-12"
		modified = "2021-08-12"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/ByteCode.MSIL.Ransomware.Pacman.yara#L1-L68"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0634303a4db2631edb40a9435444f3bdc4bc6eb745c7e43a54478e54e7507403"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "Pacman"
		tc_detection_factor = 5
		importance = 25

	strings:
		$pacman_find_encrypted_1 = {
            28 0A 00 00 06 [0-2] 6F 0D 00 00 06 [0-2] 6F 33 00 00 06 [0-2] 28 FD 01 00 06 [0-2] 28
            29 02 00 06 1F 1C 28 0E 04 00 06 [0-2] 7E 13 00 00 04 20 0F 03 00 00 28 2F 00 00 06 25
            26 28 5D 02 00 06 [0-2] 28 6D 01 00 06 [0-2] 0B 07 13 06 16 13 05 2B 31 11 06 11 05 9A
            0C 28 0A 00 00 06 [0-2] 6F 0D 00 00 06 [0-2] 6F 33 00 00 06 [0-2] 28 FD 01 00 06 [0-2]
            08 28 55 02 00 06 [0-2] 26 11 05 17 D6 13 05 11 05 11 06 8E B7 32 C7 1D 45 01 00 00 00
            F6 FF FF FF 17 2D 06 D0 1E 01 00 06 26 16 0A 38 BC 01 00 00 28 0A 00 00 06 [0-2] 6F 0D
            00 00 06 [0-2] 6F 33 00 00 06 [0-2] 28 FD 01 00 06 [0-2] 06 28 AA 04 00 06 [0-2] 14 20
            B0 0F 00 00 28 2F 00 00 06 [0-2] 1F 0A 8D 76 00 00 01 13 07 11 07 16 20 BF 0F 00 00 28
            2F 00 00 06 [0-2] A2 11 07 17 20 C2 0F 00 00 28 2F 00 00 06 [0-2] A2 11 07 18 20 C5 0F
            00 00 28 2F 00 00 06 [0-2] A2 11 07 19 20 C8 0F 00 00 28 2F 00 00 06 [0-2] A2 11 07 1A
            20 CB 0F 00 00 28 2F 00 00 06 [0-2] A2 11 07 1B 20 CE 0F 00 00 28 2F 00 00 06 [0-2] A2
        }
		$pacman_find_encrypted_2 = {
            11 07 1C 20 D1 0F 00 00 28 2F 00 00 06 [0-2] A2 11 07 1D 20 D4 0F 00 00 28 2F 00 00 06
            [0-2] A2 11 07 1E 20 C2 0F 00 00 28 2F 00 00 06 [0-2] A2 11 07 1F 09 20 D7 0F 00 00 28
            2F 00 00 06 [0-2] A2 11 07 14 14 14 28 7A 04 00 06 [0-2] 28 E2 05 00 06 [0-2] 0D 28 07
            00 00 06 28 1A 04 00 06 [0-2] 28 0A 00 00 06 [0-2] 6F 0D 00 00 06 [0-2] 6F 33 00 00 06
            [0-2] 28 FD 01 00 06 [0-2] 06 28 AA 04 00 06 [0-2] 28 E2 05 00 06 [0-2] 28 36 05 00 06
            [0-2] 2C 78 1A 45 01 00 00 00 F6 FF FF FF 7E 16 00 00 04 28 9D 02 00 06 [0-2] 28 0A 00
            00 06 [0-2] 6F 0D 00 00 06 [0-2] 6F 33 00 00 06 [0-2] 28 FD 01 00 06 [0-2] 06 28 AA 04
            00 06 [0-2] 28 E2 05 00 06 [0-2] 09 16 28 23 01 00 06 28 0A 00 00 06 [0-2] 6F 0D 00 00
            06 [0-2] 6F 33 00 00 06 [0-2] 28 FD 01 00 06 [0-2] 06 28 AA 04 00 06 [0-2] 28 E2 05 00
            06 [0-2] 28 66 04 00 06 DE 0F 25 28 4E 04 00 06 13 04 28 02 03 00 06 DE 00 06 17 D6 0A
            06 28 0A 00 00 06 [0-2] 6F 0D 00 00 06 [0-2] 6F 33 00 00 06 [0-2] 28 FD 01 00 06 [0-2]
            28 E2 04 00 06 [0-2] 3F 1B FE FF FF 1B 45 01 00 00 00 F6 FF FF FF 28 28 00 00 06 2A
        }
		$pacman_encrypt = {
            28 65 02 00 06 [0-2] 0A 16 13 05 20 00 04 00 00 13 07 06 11 07 28 2A 05 00 06 [0-2] 2C
            19 1C 45 01 00 00 00 F6 FF FF FF 17 2D 06 D0 20 01 00 06 26 11 07 13 05 2B 15 11 07 15
            D6 13 07 11 07 17 2F D0 17 45 01 00 00 00 F6 FF FF FF 20 DA 0F 00 00 28 2F 00 00 06 [0-2]
            11 05 28 9D 02 00 06 [0-2] 28 E2 02 00 06 [0-2] 28 6E 03 00 06 06 28 0A 03 00 06 [0-2]
            0B 14 13 04 14 0D 1F 0E 8D 25 00 00 01 13 0B 11 0B 16 ?? 9C 11 0B 17 ?? 9C 11 0B 18
            ?? 9C 11 0B 19 ?? 9C 11 0B 1A ?? 9C 11 0B 1B ?? 9C 11 0B 1C ?? 9C 11 0B 1D ?? 9C 11 0B
            1E 20 ?? ?? ?? ?? 9C 11 0B 1F 09 20 ?? ?? ?? ?? 9C 11 0B 1F 0A 20 ?? ?? ?? ?? 9C 11 0B
            1F 0B 1F ?? 9C 11 0B 1F 0C 1F ?? 9C 11 0B 1F 0D 1F ?? 9C 11 0B 13 06 02 11 06 11 05 07
            12 04 12 03 28 1F 01 00 06 05 2C 18 18 45 01 00 00 00 F6 FF FF FF 06 11 04 09 28 96 03
            00 06 [0-2] 0C 2B 0C 06 11 04 09 28 7E 05 00 06 [0-2] 0C 04 08 17 28 45 01 00 06 [0-2]
            13 08 20 01 04 00 00 8D 25 00 00 01 13 09 03 11 09 16 20 00 04 00 00 28 3A 03 00 06 [0-2]
            13 0A 11 0A 16 33 0C 1D 45 01 00 00 00 F6 FF FF FF DE 24 11 08 11 09 16 11 0A 28 F6 04
            00 06 2B CF 11 08 2C 11 18 45 01 00 00 00 F6 FF FF FF 11 08 28 1E 03 00 06 DC DE 0C 28
            4E 04 00 06 28 02 03 00 06 DE 00 08 28 1E 03 00 06 2A
        }

	condition:
		uint16(0)==0x5A4D and ($pacman_find_encrypted_1 and $pacman_find_encrypted_2 and $pacman_encrypt)
}
