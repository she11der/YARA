rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Chaos
{
	meta:
		description = "Detects files referencing identities associated with Chaos ransomware"
		author = "ditekShen"
		id = "18476655-1468-569e-b518-ebeaf289fbd6"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L493-L511"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "6e8dce1622dbccca6aa15040b49fc9ea05ec7192f8a79409fd7414690102d09a"
		score = 75
		quality = 67
		tags = ""

	strings:
		$s1 = "anenomous31@gmail.com" ascii wide nocase
		$s2 = "daengsocietyteam@gmail.com" ascii wide nocase
		$s3 = "RansHelp@tutanota.com" ascii wide nocase
		$s4 = "18vhBpgPhZrjJkbuT2ZyUXAnJavaJcTwEd" ascii wide
		$s5 = "bc1qlnzcep4l4ac0ttdrq7awxev9ehu465f2vpt9x0" ascii wide
		$s6 = "8AFtPnreZp28xoetUyKiQvVtwrov9PtEbMyvczdNZpBN45EUbEsrE8xYVp4NNqPrtxNjQwn3PbW3FG16EPYcPpKzMU78xN6" ascii wide
		$s7 = "bc1qu6tharwawwny28z9fj6nrxg5cqftaep9ap6z2v" ascii wide
		$s8 = "bambolina2021@virgilio.it" ascii wide nocase
		$s9 = "1EoyuvcXdAQQvStkoJZ38vdGm84StD7wjm" ascii wide
		$s10 = "1G395PJs8ciqvXPZEYb1LfUGPix9h9n3oQ" ascii wide

	condition:
		any of them
}
