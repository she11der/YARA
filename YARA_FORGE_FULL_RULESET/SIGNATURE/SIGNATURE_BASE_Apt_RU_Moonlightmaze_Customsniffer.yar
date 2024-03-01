rule SIGNATURE_BASE_Apt_RU_Moonlightmaze_Customsniffer
{
	meta:
		description = "Rule to detect Moonlight Maze sniffer tools"
		author = "Kaspersky Lab"
		id = "8cc76e4d-a956-543c-81e0-827dfdb5da1c"
		date = "2017-03-15"
		modified = "2023-12-05"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_moonlightmaze.yar#L50-L79"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7b86f40e861705d59f5206c482e1f2a5"
		hash = "927426b558888ad680829bd34b0ad0e7"
		logic_hash = "5ccf9035adc16393db4b3d461f7a20f86f538275d7806280a15508c15d9c805c"
		score = 75
		quality = 85
		tags = ""
		version = "1.1"
		original_filename = "ora;tdn"

	strings:
		$a1 = "/var/tmp/gogo" fullword
		$a2 = "myfilename= |%s|" fullword
		$a3 = "mypid,mygid=" fullword
		$a4 = "mypid=|%d| mygid=|%d|" fullword
		$a5 = "/var/tmp/task" fullword
		$a6 = "mydevname= |%s|" fullword

	condition:
		2 of ($a*)
}
