rule ARKBIRD_SOLG_MAL_Bazarloader_Oct_2021_1___FILE
{
	meta:
		description = "Detect BazarLoader implant"
		author = "Arkbird_SOLG"
		id = "d6462e74-fe1d-599e-aac8-0d0942ca42ad"
		date = "2021-10-30"
		modified = "2021-10-30"
		reference = "https://twitter.com/malwrhunterteam/status/1454154412902002692"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-10-29/Hive/MAL_BazarLoader_Oct_2021_1.yara#L1-L17"
		license_url = "N/A"
		logic_hash = "afbe02ef9e69ac5105aaae28240d6863c9c4578c0e8fd7c86c38d975cf8acdc6"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "0ba7554e7d120ce355c6995c6af95542499e4ec2f6012ed16b32a85175761a94"
		hash2 = "2b29c80a4829d3dc816b99606aa5aeead3533d24137f79b5c9a8407957e97b10"
		tlp = "white"
		adversary = "-"

	strings:
		$s1 = { 48 8b 44 24 60 c6 80 38 01 00 00 01 48 8b 44 24 60 c6 80 39 01 00 00 02 48 8b 44 24 60 c7 40 5c 03 00 00 00 b8 60 00 00 00 48 6b c0 00 48 8b 4c 24 60 48 03 41 68 48 89 44 24 20 48 8b 44 24 20 c7 00 01 00 00 00 48 8b 44 24 20 c7 40 08 02 00 00 00 48 8b 44 24 20 c7 40 0c 02 00 00 00 48 8b 44 24 20 c7 40 10 00 00 00 00 48 8b 44 24 20 c7 40 14 00 00 00 00 48 8b 44 24 20 c7 40 18 00 00 00 00 b8 60 00 00 00 48 6b c0 01 48 8b 4c 24 60 48 03 41 68 48 89 44 24 20 48 8b 44 24 20 c7 00 22 00 00 00 48 8b 44 24 20 c7 40 08 01 00 00 00 48 8b 44 24 20 c7 40 0c 01 00 00 00 48 8b 44 24 20 c7 40 10 01 00 00 00 48 8b 44 24 20 c7 40 14 01 00 00 00 48 8b 44 24 20 c7 40 18 01 00 00 00 b8 60 00 00 00 48 6b c0 02 48 8b 4c 24 60 48 03 41 68 48 89 44 24 20 48 8b 44 24 20 c7 00 23 00 00 00 48 8b 44 24 20 c7 40 08 01 00 00 00 48 8b 44 24 20 c7 40 0c 01 00 00 00 48 8b 44 24 20 c7 40 10 01 00 00 00 48 8b 44 24 20 c7 40 14 01 00 00 00 48 8b 44 24 20 c7 40 18 01 }
		$s2 = { 48 8b 44 24 50 48 8b 00 c7 40 28 10 00 00 00 48 8b 44 24 50 48 8b 00 b9 04 00 00 00 48 6b c9 00 48 8b 54 24 50 8b 92 18 01 00 00 89 54 08 2c 48 8b 44 24 50 48 8b 00 48 8b 4c 24 50 ff 10 48 8b 4c 24 50 e8 80 f8 ff ff 48 8b 4c 24 50 e8 c6 fe ff ff 48 8b 44 24 50 83 78 78 00 76 16 48 8b 44 24 50 83 78 74 00 76 0b 48 8b 44 24 50 83 78 7c 00 7f 1e 48 8b 44 24 50 48 8b 00 c7 40 28 21 00 00 00 48 8b 44 24 50 48 8b 00 48 8b 4c 24 50 ff 10 48 8b 44 24 50 48 8b 4c 24 50 8b 40 74 0f af 41 7c 89 44 24 24 8b 44 24 24 89 44 24 34 8b 44 24 24 39 44 24 34 74 1e 48 8b 44 24 50 48 8b 00 c7 40 28 48 00 00 00 48 8b 44 24 50 48 8b 00 48 8b 4c 24 50 ff 10 48 8b 44 24 38 c7 40 18 00 00 00 00 48 8b 4c 24 50 e8 0c fc ff ff 48 8b 4c 24 38 88 41 1c 48 8b 44 24 38 48 c7 40 20 00 00 00 00 48 8b 44 24 38 48 c7 40 28 00 00 00 00 48 8b 44 24 50 0f b6 40 62 85 c0 74 0d 48 8b 44 }
		$s3 = { 48 8b 84 24 c0 00 00 00 8b 80 64 01 00 00 39 44 24 30 0f 8d 82 00 00 00 48 63 44 24 30 48 8b 8c 24 c0 00 00 00 48 8b 84 c1 68 01 00 00 48 89 44 24 58 48 8b 44 24 38 48 8b 4c 24 58 8b 40 10 0f af 41 0c 48 8b 4c 24 58 48 63 49 04 48 8b 94 24 c0 00 00 00 48 8b 52 08 48 89 54 24 70 c6 44 24 20 00 4c 8b 44 24 58 45 8b 48 0c 44 8b c0 48 8b 44 24 38 48 8b 54 c8 70 48 8b 8c 24 c0 00 00 00 48 8b 44 24 70 ff 50 40 48 63 4c 24 30 48 89 84 cc 80 00 00 00 e9 5c ff ff ff 48 8b 44 24 38 8b 40 18 89 44 24 40 eb 0a 8b 44 24 40 ff c0 89 44 24 40 48 8b 44 24 38 8b 40 1c 39 44 24 40 0f 8d af 01 00 00 48 8b 44 24 38 8b 40 14 89 44 24 44 eb 0a 8b 44 24 44 ff c0 89 44 24 44 48 8b 84 24 c0 00 00 00 8b 80 88 01 00 00 39 44 24 44 0f 83 6e 01 00 00 c7 44 24 50 00 00 00 00 c7 44 24 30 00 00 00 00 eb 0a 8b 44 24 30 ff c0 89 44 24 30 48 8b 84 24 c0 00 00 00 8b 80 64 01 00 00 39 44 24 30 0f 8d e2 00 00 00 48 63 44 24 30 48 8b 8c 24 c0 00 00 00 48 8b 84 c1 68 01 00 00 48 89 44 24 58 48 8b 44 24 58 8b 4c 24 44 0f af 48 38 8b c1 89 44 24 60 c7 44 24 48 00 00 00 00 eb 0a 8b 44 24 48 ff c0 89 44 24 48 48 8b }

	condition:
		uint16(0)==0x5A4D and filesize >200KB and all of ($s*)
}