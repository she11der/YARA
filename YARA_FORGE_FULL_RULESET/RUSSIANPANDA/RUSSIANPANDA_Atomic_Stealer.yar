rule RUSSIANPANDA_Atomic_Stealer : FILE
{
	meta:
		description = "Detects Atomic Stealer targering MacOS"
		author = "RussianPanda"
		id = "259c5c33-0164-568f-aec4-4fe0a2c6d015"
		date = "2024-01-13"
		modified = "2024-01-17"
		reference = "https://www.bleepingcomputer.com/news/security/macos-info-stealers-quickly-evolve-to-evade-xprotect-detection/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1f0985c563eef9f1cda476556d29082a25bee0b3/AtomicStealer/Atomic_Stealer.yar#L1-L27"
		license_url = "N/A"
		hash = "dd8aa38c7f06cb1c12a4d2c0927b6107"
		logic_hash = "7601e508aeccba943b54e675212993920c984271f655e68c19efaf6d12cfebd5"
		score = 75
		quality = 58
		tags = "FILE"

	strings:
		$s1 = {8B 09 83 C1 (01|02|04|05|03) 39 C8 0F 85 38 00 00 00 48 8B 85}
		$s2 = {C7 40 04 00 00 00 00 C6 40 08 00 C6 40 09 00}
		$t1 = {80 75 D?}
		$t2 = {0F 57 05 ?? 1B 01 00}
		$t3 = {8A 06 34 DE 88 07 8A 46 01 34 DF 88 47 01}
		$c1 = {28 ?? 40 39}
		$c2 = {64 65 73 6B 77 61 6C 6C 65 74 73}

	condition:
		( uint32(0)==0xfeedface or uint32(0)==0xcefaedfe or uint32(0)==0xfeedfacf or uint32(0)==0xcffaedfe or uint32(0)==0xcafebabe or uint32(0)==0xbebafeca) and all of ($s*) and #s1>60 and #s2>100 or ( all of ($t*) and #t1>10 and #t2>5) or (#c1>200 and $c2)
}
