import "pe"

rule RUSSIANPANDA_Bandit_Stealer : FILE
{
	meta:
		description = "Detects the latest build of Bandit Stealer"
		author = "RussianPanda"
		id = "ed61177d-d70d-5062-8703-f2f2b9d63751"
		date = "2023-05-05"
		modified = "2023-05-05"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1f0985c563eef9f1cda476556d29082a25bee0b3/BanditStealer/bandit_stealer.yar#L3-L21"
		license_url = "N/A"
		logic_hash = "304bf05a58d5b762ffe078457739188692f4f7109db929418832c4379b21ae72"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {48 8D 35 ?? ?? B6 FF 48 8D BE DB ?? ?? FF 48 8D 87 AC ?? ?? 00 FF 30 C7 00 ?? ?? ?? ?? 50 57 31 DB 31 C9}
		$s2 = {48 FF C0 88 17 83 E9 01 8A 10 48 8D 7F 01 75 F0}

	condition:
		all of ($s*) and ( uint16(0)==0x5A4D or uint32(0)==0x4464c457f) and pe.sections[0].name contains "UPX0" and pe.sections[1].name contains "UPX1" and pe.sections[0].characteristics&pe.SECTION_MEM_EXECUTE and pe.sections[0].characteristics&pe.SECTION_MEM_WRITE and pe.sections[1].characteristics&pe.SECTION_MEM_EXECUTE and pe.sections[1].characteristics&pe.SECTION_MEM_WRITE
}
