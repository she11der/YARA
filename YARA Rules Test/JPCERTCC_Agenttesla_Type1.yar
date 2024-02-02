rule JPCERTCC_Agenttesla_Type1
{
	meta:
		description = "detect Agenttesla in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "92bfb3ab-d8d0-50ec-8ab8-ad34f1edb906"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L399-L411"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "24b9b815400967a9086048527f7aa1fce08bcd94a16aec8080aeac97045b297a"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$iestr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\IELibrary\\\\IELibrary\\\\obj\\\\Debug\\\\IELibrary.pdb"
		$atstr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\ConsoleApp1\\\\ConsoleApp1\\\\obj\\\\Debug\\\\ConsoleApp1.pdb"
		$sqlitestr = "Not a valid SQLite 3 Database File" wide

	condition:
		all of them
}