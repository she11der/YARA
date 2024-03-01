rule ARKBIRD_SOLG_APT_APT_C_61_Dec_2021_1 : FILE
{
	meta:
		description = "Detect similiar structures used in the APT-C-61 maldocs"
		author = "Arkbird_SOLG"
		id = "48054d32-6613-5a54-b19c-8e9b8f747c14"
		date = "2021-12-13"
		modified = "2021-12-14"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-12-13/APT_APT_C_61_Dec_2021_1.yara#L1-L20"
		license_url = "N/A"
		logic_hash = "be742a0ebc53f09872d5231cf367bb1e3ae04c1a70ce94610b6597e426eeb389"
		score = 75
		quality = 69
		tags = "FILE"
		hash1 = "2cc0f8a85df2b2b0dd4c6942125bf82e647e9ac7bb91467ac5c480cf5e1dd4ff"
		hash2 = "193c921f7ab12c0066014ffad37a98ee57ecd5101dae2ddeb5e39200eb704431"
		hash3 = "4ec021cc3dbb2b0de7313e41063026e3ef4777baf4dec2bdad7cd2d515bf0fe2"
		tlp = "white"
		adversary = "APT-C-61"

	strings:
		$s1 = { 3e 3c 77 3a 69 6e 73 74 72 54 65 78 74 3e 53 45 54 20 [1-4] 3c 2f 77 3a 69 6e 73 74 72 54 65 78 74 3e }
		$s2 = { 3c 2f 77 3a 72 3e 3c 77 3a 66 6c 64 53 69 6d 70 6c 65 20 77 3a 69 6e 73 74 72 3d 22 20 20 51 55 4f 54 45 20 20 }
		$s3 = { 3c 77 3a 69 6e 73 74 72 54 65 78 74 20 78 6d 6c 3a 73 70 61 63 65 3d 22 70 72 65 73 65 72 76 65 22 3e 20 3c 2f 77 3a 69 6e 73 74 72 54 65 78 74 3e }
		$s4 = { 3c 77 3a 72 3e 3c 77 3a 69 6e 73 74 72 54 65 78 74 20 78 6d 6c 3a 73 70 61 63 65 3d 22 70 72 65 73 65 72 76 65 22 3e 20 44 44 45 3c 2f 77 3a 69 6e 73 74 72 54 65 78 74 3e 3c 2f 77 3a 72 3e }

	condition:
		uint16(0)==0x4b50 and filesize >20KB and all of ($s*)
}
