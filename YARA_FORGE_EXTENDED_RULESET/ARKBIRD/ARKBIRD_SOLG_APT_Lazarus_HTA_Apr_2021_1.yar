rule ARKBIRD_SOLG_APT_Lazarus_HTA_Apr_2021_1 : FILE
{
	meta:
		description = "Detect HTA with the fake picture header as decoy used by Lazarus"
		author = "Arkbird_SOLG"
		id = "1a57251e-f0fb-541c-bf8b-f1afecf7f1c7"
		date = "2021-04-27"
		modified = "2021-04-27"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-04-27/Lazarus/APT_Lazarus_HTA_Apr_2021_1.yara#L1-L21"
		license_url = "N/A"
		logic_hash = "40c2e5b662d1999c3ae5be97604bb9ebc809a383d66331cb4b385666ce55be2a"
		score = 75
		quality = 63
		tags = "FILE"
		hash1 = "888cfc87b44024c48eed794cc9d6dea9f6ae0cc3468dee940495e839a12ee0db"
		tlp = "white"
		adversary = "Lazarus"

	strings:
		$s1 = { 0a 3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 6a 61 76 61 73 63 72 69 70 74 22 3e }
		$s2 = { 5b 27 4f 70 65 6e 54 65 78 74 46 69 6c 65 27 2c 27 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 27 }
		$s3 = { 5b 27 70 75 73 68 27 5d }
		$s4 = { 28 27 4d 5a 27 29 2c 65 5b 27 43 6c 6f 73 65 27 5d 28 29 }
		$s5 = { 5b 27 73 68 69 66 74 27 5d 28 29 }
		$s6 = { 3b 76 61 72 20 64 61 74 61 3d 5b }
		$s7 = { 62 3d 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 27 29 }

	condition:
		( uint16(0)==0x4d42 or uint16(0)==0xd8ff or uint32(0)==0x474e5089 or uint32(0)==0x38464947) and filesize >20KB and 5 of ($s*)
}
