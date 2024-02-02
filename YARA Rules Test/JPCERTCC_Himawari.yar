rule JPCERTCC_Himawari
{
	meta:
		description = "detect Himawari(a variant of RedLeaves) in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "85c33dc6-0f9b-5645-b236-f416df16b4a4"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://www.jpcert.or.jp/present/2018/JSAC2018_01_nakatsuru.pdf"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L68-L82"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "9014e6e02fb9d8fa0f646c61647ab28c3cb08f10f8f584ddd11eba27211307f5"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "3938436ab73dcd10c495354546265d5498013a6d17d9c4f842507be26ea8fafb"

	strings:
		$h1 = "himawariA"
		$h2 = "himawariB"
		$h3 = "HimawariDemo"

	condition:
		all of them
}