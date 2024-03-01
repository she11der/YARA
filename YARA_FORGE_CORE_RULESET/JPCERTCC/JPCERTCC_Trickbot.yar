rule JPCERTCC_Trickbot
{
	meta:
		description = "detect TrickBot in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "1a3c5193-bea1-5f64-be40-47bd22c09772"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://github.com/JPCERTCC/MalConfScan/"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L458-L478"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "b0c3437bc4b4f9e7b2a1562e2d514b7aad398d5e387bb79829757b5772a1ebc3"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "2153be5c6f73f4816d90809febf4122a7b065cbfddaa4e2bf5935277341af34c"

	strings:
		$tagm1 = "<mcconf><ver>" wide
		$tagm2 = "</autorun></mcconf>" wide
		$tagc1 = "<moduleconfig><autostart>" wide
		$tagc2 = "</autoconf></moduleconfig>" wide
		$tagi1 = "<igroup><dinj>" wide
		$tagi2 = "</dinj></igroup>" wide
		$tags1 = "<servconf><expir>" wide
		$tags2 = "</plugins></servconf>" wide
		$tagl1 = "<slist><sinj>" wide
		$tagl2 = "</sinj></slist>" wide
		$dllname = { 6C 00 00 00 CC 00 00 00 19 01 00 00 00 00 00 00 1A 01 }

	condition:
		all of ($tagm*) or all of ($tagc*) or all of ($tagi*) or all of ($tags*) or all of ($tagl*) or $dllname
}
