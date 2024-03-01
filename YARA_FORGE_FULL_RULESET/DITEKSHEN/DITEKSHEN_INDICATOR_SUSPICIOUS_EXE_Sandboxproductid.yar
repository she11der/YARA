import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Sandboxproductid : FILE
{
	meta:
		description = "Detects binaries and memory artifacts referencing sandbox product IDs"
		author = "ditekSHen"
		id = "5af0ace7-6ffb-5695-94c5-d8172d326662"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L130-L149"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "3a047ef7e70956e1c2222bde47036d7fff6d98cd8a5df81ea85584a3b5006d4a"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$id1 = "76487-337-8429955-22614" fullword ascii wide
		$id2 = "76487-644-3177037-23510" fullword ascii wide
		$id3 = "55274-640-2673064-23950" fullword ascii wide
		$id4 = "76487-640-1457236-23837" fullword ascii wide
		$id5 = "76497-640-6308873-23835" fullword ascii wide
		$id6 = "76487-640-1464517-23259" fullword ascii wide
		$id7 = "76487 - 337 - 8429955 - 22614" fullword ascii wide
		$id8 = "76487 - 644 - 3177037 - 23510" fullword ascii wide
		$id9 = "55274 - 640 - 2673064 - 23950" fullword ascii wide
		$id10 = "76487 - 640 - 1457236 - 23837" fullword ascii wide
		$id11 = "76497 - 640 - 6308873 - 23835" fullword ascii wide
		$id12 = "76487 - 640 - 1464517 - 23259" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and 2 of them
}
