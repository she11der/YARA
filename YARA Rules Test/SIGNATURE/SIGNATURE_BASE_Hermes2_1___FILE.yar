rule SIGNATURE_BASE_Hermes2_1___FILE
{
	meta:
		description = "Detects Hermes Ransomware as used in BAE report on FEIB"
		author = "BAE"
		id = "13397a43-04e1-5cc1-9260-9895736013f3"
		date = "2017-10-11"
		modified = "2023-12-05"
		reference = "https://baesystemsai.blogspot.de/2017/10/taiwan-heist-lazarus-tools.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_hermes_ransom.yar#L1-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "b27881f59c8d8cc529fa80a58709db36"
		logic_hash = "85a7b3ec89f2bf32e5520a7c5c84661383be71abd8dae3d072d75d5b1118db24"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "SYSTEM\\CurrentControlSet\\Control\\Nls\\Language\\"
		$s2 = "0419"
		$s3 = "0422"
		$s4 = "0423"
		$S1 = "HERMES"
		$S2 = "vssadminn"
		$S3 = "finish work"
		$S4 = "testlib.dll"
		$S5 = "shadowstorageiet"
		$u1 = "ALKnvfoi4tbmiom3t40iomfr0i3t4jmvri3tb4mvi3btv3rgt4t777"
		$u2 = "HERMES 2.1 TEST BUILD, press ok"
		$u3 = "hnKwtMcOadHwnXutKHqPvpgfysFXfAFTcaDHNdCnktA"

	condition:
		uint16(0)==0x5a4d and all of ($s*) and 3 of ($S*) and 1 of ($u*)
}