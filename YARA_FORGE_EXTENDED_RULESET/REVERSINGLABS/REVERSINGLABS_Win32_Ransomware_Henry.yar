rule REVERSINGLABS_Win32_Ransomware_Henry : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Henry ransomware."
		author = "ReversingLabs"
		id = "63627f2b-3205-5790-ba97-8e0d1da39d7c"
		date = "2021-06-14"
		modified = "2021-06-14"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.Henry.yara#L1-L80"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e6ab2a8a344d40407118e29ff78f5a0144f42a0fbdee19a80b341b59f056d292"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "Henry"
		tc_detection_factor = 5
		importance = 25

	strings:
		$find_files = {
            02 6F ?? ?? ?? ?? 0A 16 0B 2B ?? 06 07 9A 0C 08 6F ?? ?? ?? ?? 73 ?? ?? ?? ?? 28 ?? ??
            ?? ?? DE ?? 26 DE ?? 07 17 58 0B 07 06 8E 69 32 ?? 02 6F ?? ?? ?? ?? 0D 16 0B 38 ?? ??
            ?? ?? 09 07 9A 13 ?? 11 ?? 6F ?? ?? ?? ?? 19 17 73 ?? ?? ?? ?? 25 6F ?? ?? ?? ?? D4 8D
            ?? ?? ?? ?? 13 ?? 25 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 26 6F ?? ?? ?? ?? 11 ?? 6F ??
            ?? ?? ?? 11 ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 72 ?? ?? ?? ??
            28 ?? ?? ?? ?? 18 18 73 ?? ?? ?? ?? 25 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 6F ?? ?? ??
            ?? 11 ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? DE ?? 26 DE ?? 07 17 58 0B 07 09 8E 69 3F ?? ??
            ?? ?? 2A
        }
		$encrypt_files = {
            02 8E 2D ?? 72 ?? ?? ?? ?? 73 ?? ?? ?? ?? 7A 03 28 ?? ?? ?? ?? 2C ?? 72 ?? ?? ?? ?? 73
            ?? ?? ?? ?? 7A 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0B 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0C 28 ??
            ?? ?? ?? 0D 73 ?? ?? ?? ?? 13 ?? 03 08 73 ?? ?? ?? ?? 13 ?? 09 11 ?? 1F ?? 6F ?? ?? ??
            ?? 07 6F ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 17 73 ?? ?? ?? ?? 25 02 16 02 8E 69 6F ?? ?? ??
            ?? 25 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 0A 11 ?? 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ??
            25 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 26 FE ?? 09 6F ?? ?? ?? ?? DC 06 2A
        }
		$setup_environment = {
            02 28 ?? ?? ?? ?? 1B 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 16 28 ?? ?? ?? ?? 73
            ?? ?? ?? ?? 28 ?? ?? ?? ?? 1F ?? 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 1F ?? 28
            ?? ?? ?? ?? 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 1F ?? 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 28 ?? ??
            ?? ?? 02 28 ?? ?? ?? ?? 2A
        }
		$init_components = {
            02 73 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 73 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 28 ?? ?? ?? ?? 02
            7B ?? ?? ?? ?? 17 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 22 ?? ?? ?? ?? 16 19
            20 ?? ?? ?? ?? 73 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 20 ?? ?? ?? ?? 1F ?? 73
            ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ??
            ?? ?? 20 ?? ?? ?? ?? 1F ?? 73 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 16 6F ?? ??
            ?? ?? 02 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 17 6F ?? ?? ??
            ?? 02 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 22 ?? ?? ?? ?? 16 19 20 ?? ?? ?? ?? 73 ?? ?? ?? ??
            6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 20 ?? ?? ?? ?? 1F ?? 73 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02
            7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ??
            ?? ?? 73 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 17 6F ?? ?? ?? ?? 02 7B ?? ?? ??
            ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 22 ?? ?? ?? ?? 22 ?? ?? ?? ?? 73 ?? ?? ?? ?? 28 ??
            ?? ?? ?? 02 17 28 ?? ?? ?? ?? 02 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 73 ?? ?? ?? ?? 28 ?? ??
            ?? ?? 02 28 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 28 ?? ?? ?? ?? 02 7B ?? ??
            ?? ?? 6F ?? ?? ?? ?? 02 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 72 ?? ?? ?? ?? 6F ?? ?? ?? ??
            02 02 FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 16 28 ?? ?? ?? ?? 02 28 ?? ??
            ?? ?? 2A
        }

	condition:
		uint16(0)==0x5A4D and ($find_files) and ($encrypt_files) and ($setup_environment) and ($init_components)
}
