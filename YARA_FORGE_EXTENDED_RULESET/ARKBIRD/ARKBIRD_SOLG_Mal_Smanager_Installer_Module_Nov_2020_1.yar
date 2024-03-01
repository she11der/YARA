rule ARKBIRD_SOLG_Mal_Smanager_Installer_Module_Nov_2020_1 : FILE
{
	meta:
		description = "Detect installer module of Smanager (November 2020)"
		author = "Arkbird_SOLG"
		id = "364285bc-2173-5ff0-85d2-af06051a3b70"
		date = "2020-12-19"
		modified = "2020-12-19"
		reference = "https://insight-jp.nttsecurity.com/post/102glv5/pandas-new-arsenal-part-3-smanager"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-12-19/Mal_Smanager_Installer_Module_Nov_2020_1.yar#L1-L24"
		license_url = "N/A"
		logic_hash = "380d28f6cdea24f807f3c29207eb0b8888ebdfea215c53df164fe080c3917438"
		score = 75
		quality = 61
		tags = "FILE"
		hash1 = "97a5fe1d2174e9d34cee8c1d6751bf01f99d8f40b1ae0bce205b8f2f0483225c"

	strings:
		$s1 = { 63 6d 64 20 2f 63 20 73 63 68 74 61 73 6b 73 20 2f 46 20 2f 63 72 65 61 74 65 20 2f 74 6e 3a 57 69 6e 64 6f 77 73 5c 55 70 64 61 74 65 20 2f 74 72 20 22 25 73 22 20 20 20 2f 73 63 20 48 4f 55 52 4c 59 }
		$s2 = { 25 73 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 25 73 }
		$s3 = { 25 73 79 73 74 65 6d 72 6f 6f 74 25 }
		$s4 = { 25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c [1-8] 5c [1-8] 2e 63 61 62 }
		$s5 = { 53 6d 61 6e 61 67 65 72 5f 73 73 6c 2e 64 6c 6c }
		$s6 = { 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 }
		$s7 = { 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c }
		$s8 = { 43 3a 5c 77 69 6e 64 6f 77 73 5c 61 70 70 70 61 74 63 68 5c }
		$s9 = "TmV0QmlvcyBNZXNzYWdlciBSZWdpc3Rlcg==" fullword ascii
		$s10 = { 68 74 74 70 73 3d 25 5b 5e 3a 5d 3a 25 64 00 00 68 74 74 70 73 3d 00 00 73 6f 63 6b 73 3d 25 5b 5e 3a 5d 3a 25 64 00 00 73 6f 63 6b 73 3d 00 00 68 74 74 70 3d 25 5b 5e 3a 5d 3a 25 64 00 00 00 68 74 74 70 3d }
		$s11 = "&About VVSup..." fullword wide
		$s12 = "%d.tmp" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize >90KB and 7 of them
}
