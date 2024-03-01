rule REVERSINGLABS_Bytecode_MSIL_Ransomware_Harpoonlocker : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects HarpoonLocker ransomware."
		author = "ReversingLabs"
		id = "3605d354-5a33-54b1-83ad-ad514c78357b"
		date = "2022-01-27"
		modified = "2022-01-27"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/ByteCode.MSIL.Ransomware.HarpoonLocker.yara#L1-L96"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "20587f9dce5981934498d9979843a090224ba649def8b694adf7799b7060cc25"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "HarpoonLocker"
		tc_detection_factor = 5
		importance = 25

	strings:
		$encrypt_files_p1 = {
            7E ?? ?? ?? ?? 25 2D ?? 26 7E ?? ?? ?? ?? FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 25 80 ?? ??
            ?? ?? 28 ?? ?? ?? ?? 26 28 ?? ?? ?? ?? 14 FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 6F ?? ?? ??
            ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 25 7E ?? ?? ?? ?? 6F ?? ?? ?? ?? 16 6F
            ?? ?? ?? ?? 80 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0A 16 0B 2B ?? 73 ?? ?? ?? ?? 25 06 07 9A 7D
            ?? ?? ?? ?? FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 14 28 ?? ?? ?? ?? 26 07 17 58 0B 07 06 8E
            69 32 ?? 7E ?? ?? ?? ?? 2C ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0C 2B ?? 73 ?? ?? ?? ?? 0D
            09 12 ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 09 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ??
            6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 09 FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 14 28 ?? ?? ??
            ?? 26 12 ?? 28 ?? ?? ?? ?? 2D ?? DE ?? 12 ?? FE 16 ?? ?? ?? ?? 6F ?? ?? ?? ?? DC 12 ??
            12 ?? 28 ?? ?? ?? ?? 12 ?? 12 ?? 28 ?? ?? ?? ?? 11 ?? 11 ?? 59 13 ?? 72 ?? ?? ?? ?? 11
            ?? 8C ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 11 ?? 2C ?? 20 ?? ?? ?? ?? 28 ?? ?? ??
            ?? 2B ?? 2A
        }
		$encrypt_files_p2 = {
            12 ?? FE 15 ?? ?? ?? ?? 12 ?? FE 15 ?? ?? ?? ?? 12 ?? FE 15 ?? ?? ?? ?? 02 16 12 ?? 28
            ?? ?? ?? ?? 26 08 7B ?? ?? ?? ?? 0D 08 7B ?? ?? ?? ?? 20 ?? ?? ?? ?? 35 ?? 08 7B ?? ??
            ?? ?? 16 36 ?? DD ?? ?? ?? ?? 02 02 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 72
            ?? ?? ?? ?? 28 ?? ?? ?? ?? 10 ?? 03 03 6F ?? ?? ?? ?? 03 6F ?? ?? ?? ?? 6F ?? ?? ?? ??
            13 ?? 1F ?? 8D ?? ?? ?? ?? 13 ?? 03 6F ?? ?? ?? ?? 16 11 ?? 16 1F ?? 28 ?? ?? ?? ?? 03
            6F ?? ?? ?? ?? 16 11 ?? 1F ?? 1F ?? 28 ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 13 ?? 1F ?? 6A
            13 ?? 17 13 ?? 09 6E 13 ?? 2B ?? 11 ?? 17 58 13 ?? 11 ?? 11 ?? 59 13 ?? 11 ?? 11 ?? 30
            ?? 02 19 17 7E ?? ?? ?? ?? 19 20 ?? ?? ?? ?? 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 11 ??
            7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? DD ?? ?? ?? ?? 11 ?? 7E ?? ?? ?? ?? 1A 16 09 20 ??
            ?? ?? ?? 58 14 28 ?? ?? ?? ?? 0A 06 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? DD ?? ?? ?? ??
            06 1F ?? 16 16 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 0B 07 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ??
            DD ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 26 16 13 ?? 16 13 ?? 2B ?? 11 ?? 20 ?? ?? ?? ?? 2F
            ?? 09 6E 11 ?? 6A 59 13 ?? 11 ?? D4 8D ?? ?? ?? ?? 13 ?? 11 ?? 17 58 11 ?? 33 ?? 11 ??
            D4 8D ?? ?? ?? ?? 13 ?? 07 11 ?? 28 ?? ?? ?? ?? 11 ?? 16 11 ?? 8E 69 28 ?? ?? ?? ?? 11
            ?? 18 5D 2D ?? 11 ?? 8E 69 1F ?? 33 ?? 11 ?? 11 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 16 07 11
            ?? 28 ?? ?? ?? ?? 11 ?? 8E 69 28 ?? ?? ?? ?? 11 ?? 11 ?? 8E 69 58 13 ?? 11 ?? 17 58 13
            ?? 11 ?? 11 ?? 3F ?? ?? ?? ?? 11 ?? 20 ?? ?? ?? ?? 32 ?? 11 ?? 16 07 09 28 ?? ?? ?? ??
            11 ?? 8E 69 28 ?? ?? ?? ?? 2B ?? 11 ?? 16 07 11 ?? 28 ?? ?? ?? ?? 11 ?? 8E 69 28 ?? ??
            ?? ?? DE ?? 26 DE ?? 26 DE ?? 00 07 28 ?? ?? ?? ?? 26 DE ?? 26 DE ?? 00 06 28 ?? ?? ??
            ?? 26 DE ?? 26 DE ?? DC 2A
        }
		$find_files = {
            73 ?? ?? ?? ?? 0A 06 02 7D ?? ?? ?? ?? 7E ?? ?? ?? ?? 06 FE 06 ?? ?? ?? ?? 73 ?? ?? ??
            ?? 28 ?? ?? ?? ?? 2C ?? 2A 00 06 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7E ?? ??
            ?? ?? 28 ?? ?? ?? ?? DE ?? 26 DE ?? 14 0B 06 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 0B DE ?? 26
            DE ?? 07 2C ?? 07 8E 16 FE 01 2B ?? 17 0C 06 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 16 13
            ?? 2B ?? 73 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 11 ?? 9A 7D ?? ?? ?? ?? 08 2C ?? 11 ?? 7B ??
            ?? ?? ?? 28 ?? ?? ?? ?? 2B ?? 11 ?? FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 14 28 ?? ?? ?? ??
            26 11 ?? 17 58 13 ?? 11 ?? 11 ?? 8E 69 32 ?? DE ?? 26 DE ?? 08 2C ?? DD ?? ?? ?? ?? 28
            ?? ?? ?? ?? 0D 09 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 09 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 09 17
            6F ?? ?? ?? ?? 09 6F ?? ?? ?? ?? 09 6F ?? ?? ?? ?? 07 13 ?? 16 13 ?? 2B ?? 73 ?? ?? ??
            ?? 13 ?? 11 ?? 11 ?? 11 ?? 9A 7D ?? ?? ?? ?? 11 ?? 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ??
            7E ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 7E ?? ?? ?? ?? 11 ?? FE 06 ??
            ?? ?? ?? 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2D ?? 11 ?? 7B ?? ?? ?? ?? 09 28 ?? ?? ?? ?? DE
            ?? 26 DE ?? 11 ?? 17 58 13 ?? 11 ?? 11 ?? 8E 69 32 ?? 00 09 6F ?? ?? ?? ?? DE ?? 26 DE
            ?? DE ?? 26 DE ?? 2A
        }
		$change_boot = {
            02 8E 2C ?? 02 16 9A 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 28 ?? ?? ?? ?? 2A 02 16 9A 72
            ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2A 02 16 9A 72 ?? ?? ??
            ?? 6F ?? ?? ?? ?? 2C ?? 17 80 ?? ?? ?? ?? 16 80 ?? ?? ?? ?? 02 16 9A 72 ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 2C ?? 17 80 ?? ?? ?? ?? 02 16 9A 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2C ?? 28 ??
            ?? ?? ?? 2A 28 ?? ?? ?? ?? 2C ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ??
            ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ??
            ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2A 28 ?? ?? ?? ?? 2A
        }

	condition:
		uint16(0)==0x5A4D and ($change_boot) and ($find_files) and ( all of ($encrypt_files_p*))
}
