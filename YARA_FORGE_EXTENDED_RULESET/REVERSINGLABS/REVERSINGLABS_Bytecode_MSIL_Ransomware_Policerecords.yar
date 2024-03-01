rule REVERSINGLABS_Bytecode_MSIL_Ransomware_Policerecords : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects PoliceRecords ransomware."
		author = "ReversingLabs"
		id = "bacd3f98-a069-58ca-8423-01fcef7d4062"
		date = "2022-08-02"
		modified = "2022-08-02"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/ByteCode.MSIL.Ransomware.PoliceRecords.yara#L1-L79"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "55cb1a5d030c47abb1a9ca9970fb19b3124128e409bc9515c173c33b2bb49a16"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "PoliceRecords"
		tc_detection_factor = 5
		importance = 25

	strings:
		$encrypt_files = {
            00 72 ?? ?? ?? ?? 0A 73 ?? ?? ?? ?? 0B 07 06 6F ?? ?? ?? ?? 0C 04 0D 09 18 73 ?? ?? ??
            ?? 13 ?? 73 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 08 08 6F ?? ?? ?? ?? 17 73 ?? ?? ?? ?? 13 ??
            03 19 73 ?? ?? ?? ?? 13 ?? 2B ?? 11 ?? 11 ?? D2 6F ?? ?? ?? ?? 00 11 ?? 6F ?? ?? ?? ??
            25 13 ?? 15 FE 01 16 FE 01 13 ?? 11 ?? 2D ?? 11 ?? 6F ?? ?? ?? ?? 00 11 ?? 6F ?? ?? ??
            ?? 00 11 ?? 6F ?? ?? ?? ?? 00 00 DE ?? 26 00 00 DE ?? 2A
        }
		$find_files = {
            11 ?? 11 ?? 9A 13 ?? 00 00 07 11 ?? 11 ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ??
            00 11 ?? 28 ?? ?? ?? ?? 00 00 DE ?? 26 00 00 DE ?? 00 11 ?? 17 58 13 ?? 11 ?? 11 ?? 8E
            69 32 ?? 00 DE ?? 26 00 00 DE ?? 17 8D ?? ?? ?? ?? 25 16 72 ?? ?? ?? ?? A2 0C 16 13 ??
            2B ?? 00 00 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 08 11 ?? 9A 28 ?? ?? ?? ?? 00
            72 ?? ?? ?? ?? 08 11 ?? 9A 28 ?? ?? ?? ?? 18 28 ?? ?? ?? ?? 00 00 DE ?? 26 00 00 DE ??
            00 11 ?? 17 58 13 ?? 11 ?? 08 8E 69 FE 04 13 ?? 11 ?? 2D ?? 00 00 72 ?? ?? ?? ?? 1D 28
            ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 00 1D 28 ?? ?? ?? ?? 72 ?? ??
            ?? ?? 28 ?? ?? ?? ?? 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 00 00 DE ?? 26 00 00 DE ?? 7E ?? ??
            ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0D 09 72 ?? ?? ?? ?? 17 8C ?? ?? ?? ?? 1A 6F ?? ??
            ?? ?? 00 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 72 ?? ?? ?? ?? 16 8C
            ?? ?? ?? ?? 1A 6F ?? ?? ?? ?? 00 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 11
            ?? 72 ?? ?? ?? ?? 17 8C ?? ?? ?? ?? 1A 6F ?? ?? ?? ?? 00 7E ?? ?? ?? ?? 72 ?? ?? ?? ??
            6F ?? ?? ?? ?? 13 ?? 11 ?? 72 ?? ?? ?? ?? 17 8C ?? ?? ?? ?? 1A 6F ?? ?? ?? ?? 00 7E ??
            ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 17 6F
            ?? ?? ?? ?? 00 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 72 ?? ?? ?? ??
            72 ?? ?? ?? ?? 17 6F ?? ?? ?? ?? 00 07 FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 73 ?? ?? ?? ??
            13 ?? 11 ?? 6F ?? ?? ?? ?? 00 73 ?? ?? ?? ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 26 2A
        }
		$desktop_kill_tick = {
            02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 00 16 28 ?? ?? ?? ?? 0A 06 72 ?? ?? ?? ?? 28 ?? ?? ??
            ?? 0B 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0C 08 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0D 09 72 ?? ??
            ?? ?? 28 ?? ?? ?? ?? 13 ?? 07 28 ?? ?? ?? ?? 13 ?? 11 ?? 2C ?? 00 07 28 ?? ?? ?? ?? 00
            00 11 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 2C ?? 00 11 ?? 28 ?? ?? ?? ?? 00 00 02 7B ?? ?? ??
            ?? 6F ?? ?? ?? ?? 00 2A
        }
		$drop_ransom_note = {
            00 16 28 ?? ?? ?? ?? 0A 06 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0B 00 07 72 ??
            ?? ?? ?? 6F ?? ?? ?? ?? 00 07 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 00 07 72 ?? ?? ?? ?? 6F ??
            ?? ?? ?? 00 07 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 00 07 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 00 07
            72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 00 07 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 00 00 DE ?? 07 2C ??
            07 6F ?? ?? ?? ?? 00 DC 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28
            ?? ?? ?? ?? 26 2A
        }

	condition:
		uint16(0)==0x5A4D and ($find_files) and ($encrypt_files) and ($desktop_kill_tick) and ($drop_ransom_note)
}
