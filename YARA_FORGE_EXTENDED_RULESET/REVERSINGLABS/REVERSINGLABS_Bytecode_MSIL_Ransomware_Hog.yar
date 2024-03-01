rule REVERSINGLABS_Bytecode_MSIL_Ransomware_Hog : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Hog ransomware."
		author = "ReversingLabs"
		id = "b4f26acf-5ff1-5c49-8cfa-8f619af84efd"
		date = "2021-10-12"
		modified = "2021-10-12"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/ByteCode.MSIL.Ransomware.Hog.yara#L1-L70"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c5cbc79fee9083ed3befa6b0d348f2d38064bb9012b8f0ca11afd7137243866d"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "Hog"
		tc_detection_factor = 5
		importance = 25

	strings:
		$generate_key = {
            73 ?? ?? ?? ?? 0A 73 ?? ?? ?? ?? 0B 1A 8D ?? ?? ?? ?? 0C 2B ?? 07 08 6F ?? ?? ?? ?? 08
            16 28 ?? ?? ?? ?? 0D 06 72 ?? ?? ?? ?? 09 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 5E 28 ?? ?? ??
            ?? 6F ?? ?? ?? ?? 26 02 25 17 59 10 ?? 16 30 ?? 06 6F ?? ?? ?? ?? 13 ?? DE ?? 07 2C ??
            07 6F ?? ?? ?? ?? DC 11 ?? 2A
        }
		$find_files = {
            16 7E ?? ?? ?? ?? 73 ?? ?? ?? ?? 0A 06 16 16 6F ?? ?? ?? ?? 2D ?? DD ?? ?? ?? ?? 00 1F
            ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 80 ?? ?? ?? ?? 7E ?? ?? ?? ?? 28 ?? ??
            ?? ?? 80 ?? ?? ?? ?? 73 ?? ?? ?? ?? 0B 07 72 ?? ?? ?? ?? 7E ?? ?? ?? ?? 28 ?? ?? ?? ??
            6F ?? ?? ?? ?? 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 7E ??
            ?? ?? ?? 6F ?? ?? ?? ?? 17 31 ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 25 2D ?? 26 7E ?? ?? ??
            ?? FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 25 80 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0C
            2B ?? 08 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 08 6F ?? ?? ?? ?? 2D ?? DE ?? 08 2C ?? 08 6F ??
            ?? ?? ?? DC 28 ?? ?? ?? ?? DE ?? 07 2C ?? 07 6F ?? ?? ?? ?? DC DE ?? 26 28 ?? ?? ?? ??
            DE ?? 06 2C ?? 06 6F ?? ?? ?? ?? DC 2A
        }
		$encrypt_files_p1 = {
            02 7E ?? ?? ?? ?? 6F ?? ?? ?? ?? 3A ?? ?? ?? ?? 02 73 ?? ?? ?? ?? 6F ?? ?? ?? ?? 7E ??
            ?? ?? ?? 31 ?? DD ?? ?? ?? ?? 73 ?? ?? ?? ?? 0A 06 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ??
            ?? ?? ?? 06 1F ?? 8D ?? ?? ?? ?? 25 D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 19
            73 ?? ?? ?? ?? 0B 02 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0C 08 06 6F ?? ?? ??
            ?? 17 73 ?? ?? ?? ?? 0D 08 06 6F ?? ?? ?? ?? 16 06 6F ?? ?? ?? ?? 8E 69 6F ?? ?? ?? ??
            07 09 6F ?? ?? ?? ?? DE ?? 09 2C ?? 09 6F ?? ?? ?? ?? DC DE ?? 08 2C ?? 08 6F ?? ?? ??
            ?? DC DE ?? 07 2C ?? 07 6F ?? ?? ?? ?? DC DE ?? 06 2C ?? 06 6F ?? ?? ?? ?? DC 02 28 ??
            ?? ?? ?? DE ?? 26 DE ?? 2A
        }
		$encrypt_files_p2 = {
            73 ?? ?? ?? ?? 0A 06 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 06 1F ?? 8D ?? ?? ??
            ?? 25 D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 6F ?? ?? ?? ?? 0B
            73 ?? ?? ?? ?? 0C 08 06 6F ?? ?? ?? ?? 17 73 ?? ?? ?? ?? 0D 09 07 16 07 8E 69 6F ?? ??
            ?? ?? 09 6F ?? ?? ?? ?? DE ?? 09 2C ?? 09 6F ?? ?? ?? ?? DC 08 6F ?? ?? ?? ?? 28 ?? ??
            ?? ?? 10 ?? DE ?? 08 2C ?? 08 6F ?? ?? ?? ?? DC 02 13 ?? DE ?? 06 2C ?? 06 6F ?? ?? ??
            ?? DC 26 DE ?? 02 2A 11 ?? 2A
        }

	condition:
		uint16(0)==0x5A4D and ($find_files) and ($generate_key) and ( all of ($encrypt_files_p*))
}
