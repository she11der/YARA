import "elf"

rule REVERSINGLABS_Linux_Virus_Vit : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Vit virus."
		author = "ReversingLabs"
		id = "4515fe43-4c5a-521d-82b7-273823f0c64e"
		date = "2024-02-18"
		date = "2024-02-18"
		modified = "2023-06-07"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/virus/Linux.Virus.Vit.yara#L3-L36"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2fba7a081dfca85aee5c7f3b33414b799ed52ca6aa5bbf031da040aaa75acde9"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Virus"
		tc_detection_factor = 5
		importance = 25

	strings:
		$vit_entry_point = {
        55 89 E5 81 EC 40 31 00 00 57 56 50 53 51 52 C7 85 D8 CE FF FF 00 00 00 00 C7 85 D4
        CE FF FF 00 00 00 00 C7 85 FC CF FF FF CA 08 00 00 C7 85 F8 CF FF FF B8 06 00 00 C7
        85 F4 CF FF FF AD 08 00 00 C7 85 F0 CF FF FF 50 06 00 00 6A 00 6A 00 8B 45 08 50 E8
        18 FA FF FF 89 C6 83 C4 0C 85 F6 0F 8C E6 01 00 00 6A 00 68 ?? ?? ?? ?? 56 E8 2E FA
        FF FF 83 C4 0C 85 C0 0F 8C C4 01 00 00 8B 85 FC CF FF FF 50 8D 85 00 D0 FF FF 50 56
        E8 2A FA FF FF 89 C2 8B 85 FC CF FF FF 83 C4 0C 39 C2 0F 85 9D 01 00 00 56 E8 E1 F9
        FF FF BE FF FF FF FF 6A 00 6A 00 E9
      }
		$vit_str = "vi324.tmp"

	condition:
		uint32(0)==0x464C457F and $vit_entry_point at elf.entry_point and $vit_str
}
