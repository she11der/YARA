rule REVERSINGLABS_Bytecode_MSIL_Ransomware_Zerolocker : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects ZeroLocker ransomware."
		author = "ReversingLabs"
		id = "291b5640-387c-54d9-97a6-13823932fa60"
		date = "2021-08-12"
		modified = "2021-08-12"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/ByteCode.MSIL.Ransomware.ZeroLocker.yara#L1-L70"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "147e4b390bcfaff8f05059c1d9a98b50f544fc32e820406417894fe5046e0f71"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "ZeroLocker"
		tc_detection_factor = 5
		importance = 25

	strings:
		$encrypt_routine_1 = {
            00 28 5B 00 00 0A 20 ?? 07 00 00 28 60 00 00 06 13 09 20 ?? 07 00 00 28 60 00 00 06 13 
            0B 02 03 20 ?? 07 00 00 28 60 00 00 06 20 ?? 07 00 00 28 60 00 00 06 73 ?? 00 00 0A 7D 
            1B 00 00 04 20 ?? 07 00 00 28 60 00 00 06 13 0B 02 04 20 ?? 07 00 00 28 60 00 00 06 20 
            ?? 07 00 00 28 60 00 00 06 73 ?? 00 00 0A 7D 1C 00 00 04 20 ?? 07 00 00 28 60 00 00 06 
            13 0B 02 7B 1C 00 00 04 20 ?? 07 00 00 28 60 00 00 06 6A 6F ?? 00 00 0A 00 20 ?? 07 00 
            00 28 60 00 00 06 13 0B 20 ?? 07 00 00 28 60 00 00 06 8D 1E 00 00 01 0A 20 ?? 07 00 00 
            28 60 00 00 06 13 0B 20 ?? 07 00 00 28 60 00 00 06 6A 13 04 20 ?? 07 00 00 28 60 00 00 
            06 13 0B 02 7B 1B 00 00 04 6F ?? 00 00 0A [0-2] 13 05 20 ?? 07 00 00 28 60 00 00 06 13 
            0B 73 ?? 00 00 0A 0C 20 ?? 07 00 00 28 60 00 00 06 13 0B 00 0E 05 20 ?? 07 00 00 28 60 
            00 00 06 59 13 0C 11 0C 45 02 00 00 00 02 00 00 00 ?? 00 00 00 2B ?? 00 20 ?? 07 00 00 
            28 60 00 00 06 13 0B 02 7B 1C 00 00 04 08 05 0E 04 6F ?? 00 00 0A [0-2] 20 ?? 07 00 00 
            28 60 00 00 06 73 ?? 00 00 0A 0B 2B ?? 00 20 ?? 07 00 00 28 60 00 00 06 13 0B 02 7B 1C 
            00 00 04 08 05 0E 04 6F ?? 00 00 0A [0-2] 20 ?? 07 00 00 28 60 00 00 06 73 ?? 00 00 0A 
            0B 00 2B 62 20 ?? 07 00 00 28 60 00 00 06 13 0B 02 7B 1B 00 00 04 06 20 ?? 07 00 00 28 
            60 00 00 06 20 ?? 07 00 00 28 60 00 00 06 6F ?? 00 00 0A [0-2] 0D 20 ?? 07 00 00 28 60
        }
		$encrypt_routine_2 = {
            00 00 06 13 0B 07 06 20 ?? 07 00 00 28 60 00 00 06 09 6F ?? 00 00 0A 00 20 ?? 07 00 00 
            28 60 00 00 06 13 0B 11 04 09 6A D6 13 04 00 20 ?? 07 00 00 28 60 00 00 06 13 0B 11 04 
            11 05 FE 04 13 0D 11 0D 2D 86 ?? 45 01 00 00 00 F6 FF FF FF 17 2D 06 D0 4F 00 00 06 26 
            20 ?? 07 00 00 28 60 00 00 06 13 0B 07 6F ?? 00 00 0A 00 20 ?? 07 00 00 28 60 00 00 06 
            13 0B 02 7B 1B 00 00 04 6F ?? 00 00 0A 00 20 ?? 07 00 00 28 60 00 00 06 13 0B 02 7B 1C 
            00 00 04 6F ?? 00 00 0A 00 20 ?? 07 00 00 28 60 00 00 06 13 0B 0E 05 20 ?? 07 00 00 28 
            60 00 00 06 FE 01 13 0D 11 0D 2C 32 ?? 45 01 00 00 00 F6 FF FF FF 20 ?? 07 00 00 28 60 
            00 00 06 13 0B 03 73 ?? 00 00 0A 13 06 20 ?? 07 00 00 28 60 00 00 06 13 0B 11 06 6F ?? 
            00 00 0A 00 00 20 ?? 07 00 00 28 60 00 00 06 13 0B 0E 05 20 ?? 07 00 00 28 60 00 00 06 
            FE 01 13 0D 11 0D 2C ?? [0-20] 20 ?? 07 00 00 28 60 00 00 06 13 0B 03 73 ?? 00 00 0A 13 
            07 20 ?? 07 00 00 28 60 00 00 06 13 0B 11 07 6F ?? 00 00 0A 00 00 20 ?? ?? 00 00 28 60 
            00 00 06 13 0B 02 7B 1B 00 00 04 6F ?? 00 00 0A 00 20 ?? ?? 00 00 28 60 00 00 06 13 0B 
            02 7B 1C 00 00 04 6F ?? 00 00 0A 00 DD 3B 01 00 00 11 0A 2B 0D 11 0A 20 ?? ?? 00 00 28
        }
		$encrypt_routine_3 = { 
            60 00 00 06 58 20 ?? 08 00 00 28 60 00 00 06 13 0A 45 26 00 00 00 00 00 00 00 ?? FC FF 
            FF ?? FC FF FF ?? FC FF FF ?? FC FF FF ?? FC FF FF ?? FC FF FF ?? FC FF FF ?? ?? FF FF 
            ?? FD FF FF ?? FD FF FF ?? FD FF FF 00 00 00 00 ?? FD FF FF ?? FD FF FF ?? FD FF FF ?? 
            FD FF FF ?? FD FF FF ?? FD FF FF ?? ?? FF FF ?? FD FF FF ?? FD FF FF ?? FD FF FF ?? ?? 
            FF FF ?? FE FF FF ?? FE FF FF ?? FE FF FF ?? FE FF FF ?? FE FF FF ?? FE FF FF ?? FE FF 
            FF ?? FE FF FF E8 FE FF FF FC FE FF FF 10 FF FF FF 11 FF FF FF 29 FF FF FF 41 FF FF FF 
            DE 6D 11 0B 13 0A 11 09 20 ?? 08 00 00 28 60 00 00 06 30 16 ?? 45 01 00 00 00 F6 FF FF 
            FF 20 ?? 08 00 00 28 60 00 00 06 2B 02 11 09 45 02 00 00 00 00 00 00 00 11 FF FF FF DE 
            34 75 4B 00 00 01 14 FE 03 11 09 20 ?? 08 00 00 28 60 00 00 06 FE 03 5F 11 0A 20 ?? 08 
            00 00 28 60 00 00 06 FE 01 5F FE 11 74 4B 00 00 01 28 57 00 00 0A DE 93 20 ?? 08 00 00 
            28 60 00 00 06 28 ?? 00 00 0A 
        }

	condition:
		uint16(0)==0x5A4D and ($encrypt_routine_1 and $encrypt_routine_2 and $encrypt_routine_3)
}
