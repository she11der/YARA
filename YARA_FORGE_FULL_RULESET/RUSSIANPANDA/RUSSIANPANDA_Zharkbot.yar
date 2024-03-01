rule RUSSIANPANDA_Zharkbot : FILE
{
	meta:
		description = "Detects ZharkBot"
		author = "RussianPanda"
		id = "6c622216-2f70-5b7c-ba22-103922d65720"
		date = "2024-01-21"
		modified = "2024-01-22"
		reference = "https://x.com/ViriBack/status/1749184882822029564?s=20"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1f0985c563eef9f1cda476556d29082a25bee0b3/ZharkBot/zharkbot.yar#L1-L15"
		license_url = "N/A"
		hash = "d53ce8c0a8a89c2e3eb080849da8b1c47eaac614248fc55d03706dd5b4e10bdd"
		logic_hash = "b149bc61b3e1d2bcc68481ffe2b08fe31e0837c58174b47e2e0b693a5cef8a9a"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {F7 EA C1 FA 04 8B C2 C1 E8 1F 03 C2 8B 55 ?? 0F BE C0 8A CA 6B C0 ?? 2A C8 80 C1}
		$s2 = {F7 E2 C1 EA 04 0F BE C2 8B 55 ?? 8A CA 6B C0 ?? 2A C8 80 C1 ?? 30 8C 15}

	condition:
		uint16(0)==0x5A4D and #s1>5 and #s2>5 and filesize <500KB
}
