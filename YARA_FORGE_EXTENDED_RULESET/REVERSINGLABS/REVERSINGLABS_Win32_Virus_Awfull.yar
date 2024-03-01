import "pe"

rule REVERSINGLABS_Win32_Virus_Awfull : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Awfull virus."
		author = "ReversingLabs"
		id = "34104923-b401-5d39-883b-aa9a5a8e64f3"
		date = "2020-07-15"
		modified = "2020-07-15"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/virus/Win32.Virus.Awfull.yara#L3-L33"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "84a4faee4cbbb3387ad25bd9230c6482b8db461bc008312bc782f23e3df2eae3"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Virus"
		tc_detection_name = "Awfull"
		tc_detection_factor = 5
		importance = 25

	strings:
		$awfull_body = {
              60 E8 ?? 00 00 00 8B 64 24 08 EB ?? [0-256]
              33 D2 64 FF 32 64 89 22 33 C0 C7 00 00 00 00 00 33 D2 64 8F 02
              5A 64 (8B 0D | 67 8B 0E ) 14 00 [0-2] E3 03 FA    
              EB FD 61 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 0B ED 74 ?? 
              [0-128] (BE | 8B 35) ?? ?? ?? ?? 03 F5 B9 ?? ?? ?? ??    
              56 5F AC F6 D0 AA 49 E3 02 EB F7
        }

	condition:
		uint16(0)==0x5A4D and ($awfull_body at pe.entry_point)
}
