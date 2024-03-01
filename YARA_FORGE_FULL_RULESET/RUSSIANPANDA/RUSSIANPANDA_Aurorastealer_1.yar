rule RUSSIANPANDA_Aurorastealer_1
{
	meta:
		description = "Detects the Build/Group IDs if present / detects an unobfuscated AuroraStealer binary; tested on version 22.12.2022"
		author = "RussianPanda"
		id = "1a94096f-c838-5272-856e-42efbd123a31"
		date = "2023-02-07"
		modified = "2023-05-05"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1f0985c563eef9f1cda476556d29082a25bee0b3/AuroraStealer/AuroraStealer.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "7a9900266a0dfa7bf0ea91a0260a1d30bd7799a491fba87db083f4fea4115f2a"
		score = 50
		quality = 85
		tags = ""

	strings:
		$b1 = { 48 8D 0D ?? ?? 04 00 E8 ?? ?? EF FF }
		$go = "Go build ID"
		$machineid = "MachineGuid"

	condition:
		all of them
}
