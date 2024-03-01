import "pe"

rule REVERSINGLABS_Win32_Virus_Elerad : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Elerad virus."
		author = "ReversingLabs"
		id = "0307a136-ea2c-584c-bfda-f41e2c46fd09"
		date = "2020-07-15"
		modified = "2020-07-15"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/virus/Win32.Virus.Elerad.yara#L3-L33"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "930594bf99daf55ef02542ce7b393c1c23ead75946b3da3b555102a2e7142e33"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Virus"
		tc_detection_name = "Elerad"
		tc_detection_factor = 5
		importance = 25

	strings:
		$elerad_body = {
            EB 77 60 E8 09 00 00 00 8B 64 24 08 E9 DD 01 00 00 33 D2 64 FF 32 64 89 22 50 8B D8 B9 FF 00 00 00 81 38 2E 65 78 65 74
            08 40 E2 F5 E9 BD 01 00 00 32 D2 38 50 04 0F 85 B2 01 00 00 33 D2 80 38 5C 74 07 3B C3 74 07 48 E2 F4 88 10 8B D0 58 BE
            00 00 E6 77 BF 23 C1 AB 00 EB 3E 60 E8 09 00 00 00 8B 64 24 08 E9 84 01 00 00 33 D2 64 FF 32 64 89 22 BE 00 00 E6 77 EB
            20 68 ?? ?? ?? ?? 60 8B 74 24 24 E8 09 00 00 00 8B 64 24 08 E9 5D 01 00 00 33 D2 64 FF 32 64 89 22 E8 00 00 00 00 5D 81
            ED ?? ?? ?? ?? 81 FF 23 C1 AB 00 75 0C 89 95 22 12 40 00 89 85 1E 12 40 00 BA ?? ?? ?? ?? B9 09 02 00 00 8D 85 D0 10 40
            00 31 10 83 C0 04 E2 F9
        }

	condition:
		uint16(0)==0x5A4D and ($elerad_body at pe.entry_point)
}
