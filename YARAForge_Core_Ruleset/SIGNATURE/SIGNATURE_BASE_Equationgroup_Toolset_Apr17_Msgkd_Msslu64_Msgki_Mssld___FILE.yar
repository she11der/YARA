rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Msgkd_Msslu64_Msgki_Mssld___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "cb6d4098-8ede-58ba-9851-7c8b360fb606"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3231-L3256"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "f61ce58356ffca197d4a2a4aae43414bcb8f2f284dbee818124dd450f4b50cb9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9ab667b7b5b9adf4ff1d6db6f804824a22c7cc003eb4208d5b2f12809f5e69d0"
		hash2 = "320144a7842500a5b69ec16f81a9d1d4c8172bb92301afd07fb79bc0eca81557"
		hash3 = "c10f4b9abee0fde50fe7c21b9948a2532744a53bb4c578630a81d2911f6105a3"
		hash4 = "551174b9791fc5c1c6e379dac6110d0aba7277b450c2563e34581565609bc88e"
		hash5 = "8419866c9058d738ebc1a18567fef52a3f12c47270f2e003b3e1242d86d62a46"

	strings:
		$s1 = "PQRAPAQSTUVWARASATAUAVAW" fullword ascii
		$s2 = "SQRUWVAWAVAUATASARAQAP" fullword ascii
		$s3 = "iijymqp" fullword ascii
		$s4 = "AWAVAUATASARAQI" fullword ascii
		$s5 = "WARASATAUAVM" fullword ascii
		$op1 = { 0c 80 30 02 48 83 c2 01 49 83 e9 01 75 e1 c3 cc }
		$op2 = { e8 10 66 0d 00 80 66 31 02 48 83 c2 02 49 83 e9 }
		$op3 = { 48 b8 53 a5 e1 41 d4 f1 07 00 48 33 }

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 2 of ($s*) or all of ($op*))
}