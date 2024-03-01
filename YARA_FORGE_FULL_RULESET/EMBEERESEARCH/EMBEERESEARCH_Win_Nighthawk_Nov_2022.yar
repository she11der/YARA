rule EMBEERESEARCH_Win_Nighthawk_Nov_2022 : FILE
{
	meta:
		description = "Experimental Yara rule for patterns observed in Nighthawk"
		author = "Embee_Research @ Huntress"
		id = "853b0623-ea35-5055-90d0-bb2b5aea8ecd"
		date = "2022-11-23"
		modified = "2023-10-18"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/2022/win_nighthawk_nov_2022.yar#L1-L100"
		license_url = "N/A"
		logic_hash = "ef39067c12396db1de2feb560ff5628cbb3126e34e6318e88bdb08f6eb7940fb"
		score = 50
		quality = 67
		tags = "FILE"
		vendor = "Huntress"
		sharing = "TLP:White"

	strings:
		$s1 = {c6 ad b1 fd}
		$s2 = {97 16 5f fa}
		$s3 = {d0 05 89 e9}
		$s4 = {bf 27 3f 97}
		$s5 = {d7 12 2f 49}
		$s6 = {f2 b7 78 2b}
		$s7 = {09 c4 e6 fb}
		$s8 = {54 af d9 1a}
		$s9 = {04 e4 72 6e}
		$s10 = {4f 06 7d 7d}
		$s11 = {93 ee 23 66}
		$g1 = {bf bf d1 d5}
		$g2 = {7c 75 84 91}
		$g3 = {47 fb eb 2b}
		$g4 = {42 24 3d 39}
		$g5 = {e7 e9 ef ee}
		$g6 = {47 fd 36 2e}
		$g7 = {39 de 19 3d}
		$g8 = {20 df db f7}
		$g9 = {45 34 2a 41}
		$g10 = {7d 1c 44 2e}
		$g11 = {7d 28 44 2e}
		$g12 = {94 36 65 8d}
		$ror_1 = {48 ff c2 c1 c9 08 0f be c0 03 c8}
		$ror_2 = {41 c1 c8 08 41 80 fa 61}
		$gs_offset_1 = {65 48 8b 04 25 30 00 00 00 48 8b 48 60 4c 8b 59 18}
		$gs_offset_2 = {65 48 8b 04 25 30 00 00 00 8b d9 48 8b 50 60 4c 8b 4a 18 49 83 c1 10}
		$shr_block = {c1 e9 02 33 ca 66 d1 e8 d1 e9 33 ca c1 e9 02 33 ca c1 e2 0f}

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and ((((3 of ($s*)) or (3 of ($g*))) and ((1 of ($ror*)) and (1 of ($gs_offset*)))) or $shr_block)
}
