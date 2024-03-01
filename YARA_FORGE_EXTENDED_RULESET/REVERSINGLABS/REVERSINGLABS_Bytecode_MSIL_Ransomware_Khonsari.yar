rule REVERSINGLABS_Bytecode_MSIL_Ransomware_Khonsari : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Khonsari ransomware."
		author = "ReversingLabs"
		id = "c3c64256-af1f-5a9d-8a59-8d72993bb8da"
		date = "2022-01-27"
		modified = "2022-01-27"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/ByteCode.MSIL.Ransomware.Khonsari.yara#L1-L68"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f1003b7863215bcd8e5cdce8ce40551105fb668ea2b8ac765909f9fa5373e6ca"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "Khonsari"
		tc_detection_factor = 5
		importance = 25

	strings:
		$find_files = {
            73 ?? ?? ?? ?? 0A 73 ?? ?? ?? ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 72 ?? ?? ?? ??
            13 ?? 11 ?? 13 ?? 11 ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 28 ?? ?? ?? ?? 0B
            16 0C 2B ?? 07 08 9A 0D 09 6F ?? ?? ?? ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 72 ??
            ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 06 09
            6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 08 17 58 0C 08 07 8E 69 32 ?? 06 1B 28 ?? ?? ?? ?? 6F ??
            ?? ?? ?? 06 1F ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 06 1F ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ??
            06 1F ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11
            ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 06 1F ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ??
            06 6F ?? ?? ?? ?? 13 ?? 38 ?? ?? ?? ?? 12 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 28 ?? ?? ?? ??
            6F ?? ?? ?? ?? 13 ?? 2B ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 2D ?? 00 11
            ?? 7E ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 11 ?? 11 ?? 72 ??
            ?? ?? ?? 13 ?? 11 ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 28 ?? ?? ??
            ?? 28 ?? ?? ?? ?? DE ?? 26 DE ?? 11 ?? 6F ?? ?? ?? ?? 2D ?? DE ?? 11 ?? 2C ?? 11 ?? 6F
            ?? ?? ?? ?? DC DE ?? 26 DE ?? 12 ?? 28 ?? ?? ?? ?? 3A ?? ?? ?? ?? DE ?? 12 ?? FE 16 ??
            ?? ?? ?? 6F ?? ?? ?? ?? DC 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ??
            28 ?? ?? ?? ?? 26 2A
        }
		$get_key = {
            73 ?? ?? ?? ?? 0A 06 12 ?? FE 15 ?? ?? ?? ?? 12 ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11
            ?? 13 ?? 11 ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7D
            ?? ?? ?? ?? 12 ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 13 ?? 11 ?? 13 ?? 11 ?? 72 ??
            ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 07 6F ??
            ?? ?? ?? 06 02 7B ?? ?? ?? ?? 17 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 13 ?? 11
            ?? 13 ?? 11 ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 06 02 7B ?? ?? ?? ?? 17 6F ??
            ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0C DE ?? 06 2C ?? 06 6F ?? ?? ?? ?? DC 08 2A
        }
		$encrypt_files = {
            28 ?? ?? ?? ?? 0A 06 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 13 ?? 11 ?? 6F ?? ?? ?? ?? 06 20
            ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 13 ?? 11 ?? 13 ?? 11 ?? 13 ?? 11 ?? 13 ?? 11 ?? 6F ?? ??
            ?? ?? 06 19 6F ?? ?? ?? ?? 06 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 06 02 7B ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 06 06 6F ?? ?? ?? ?? 06 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 0B 02 03 07 28 ?? ??
            ?? ?? 0C DE ?? 07 2C ?? 07 6F ?? ?? ?? ?? DC 06 2C ?? 06 6F ?? ?? ?? ?? DC 08 2A
        }

	condition:
		uint16(0)==0x5A4D and ($find_files) and ($get_key) and ($encrypt_files)
}