rule ELCEEF_Suspicious_Onenote
{
	meta:
		description = "Detects OneNote documents with FileDataStoreObject structure containing: PE32, shortcut files (*.lnk), encoded JS, Windows Help File (*.chm), or batch script"
		author = "marcin@ulikowski.pl"
		id = "57f6fc7f-666f-5887-ac97-513588415757"
		date = "2023-01-22"
		modified = "2023-02-21"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/rules/Suspicious_OneNote.yara#L1-L23"
		license_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/LICENSE"
		logic_hash = "b65f0976b71c1e827ecce09f0c435d9ffa6a5d3b3a41401efc6a14b6259af4ad"
		score = 65
		quality = 75
		tags = ""
		hash1 = "f408ef3fa89546483ba63f58be3f27a98795655eb4b9b6217cbe302a5ba9d5f7"
		hash2 = "5306fa7940b4d67dfb031fd315b661cecb2ce81e2f34c9393e1826df0f0bbdc5"
		hash3 = "e1d34ad42938a777d80f3ee4c206de14021f13ab79600168b85894fdb0867b3e"
		hash4 = "9e89231578d8b9b190de3288fd10f43cf11a24963a8b0a76f0c46170deda59fd"
		hash5 = "6778c59a29e25d722230163bea272ece58d2d3696fbce4347c20104e8fb735dc"

	strings:
		$magic = { ae b1 53 78 d0 29 96 d3 }
		$fdso_pe32 = { a4 c4 8d 4d 0b 7a 9e ac [20] 4d 5a }
		$fdso_bat = { a4 c4 8d 4d 0b 7a 9e ac [20] 40 65 63 68 6f 20 6f 66 66 }
		$fdso_lnk = { a4 c4 8d 4d 0b 7a 9e ac [20] 4c 00 00 00 01 14 02 00 }
		$fdso_jse = { a4 c4 8d 4d 0b 7a 9e ac [20] 23 40 7e 5e }
		$fdso_chm = { a4 c4 8d 4d 0b 7a 9e ac [20] 49 54 53 46 03 }

	condition:
		$magic at 8 and 1 of ($fdso_*)
}
