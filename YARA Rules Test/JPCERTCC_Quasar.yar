rule JPCERTCC_Quasar
{
	meta:
		description = "detect QuasarRAT in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "f0a81a46-c19b-5012-a1a2-f2f4310fcde3"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://github.com/JPCERTCC/MalConfScan/"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L495-L513"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "a3bb45f2ea217ae1825d80e1ead9c3e47ca88575c960ce1f9feb2db09f489e08"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "390c1530ff62d8f4eddff0ac13bc264cbf4183e7e3d6accf8f721ffc5250e724"

	strings:
		$quasarstr1 = "Client.exe" wide
		$quasarstr2 = "({0}:{1}:{2})" wide
		$sql1 = "SELECT * FROM Win32_DisplayConfiguration" wide
		$sql2 = "{0}d : {1}h : {2}m : {3}s" wide
		$sql3 = "SELECT * FROM FirewallProduct" wide
		$net1 = "echo DONT CLOSE THIS WINDOW!" wide
		$net2 = "freegeoip.net/xml/" wide
		$net3 = "http://api.ipify.org/" wide
		$resource = { 52 00 65 00 73 00 6F 00 75 00 72 00 63 00 65 00 73 00 00 17 69 00 6E 00 66 00 6F 00 72 00 6D 00 61 00 74 00 69 00 6F 00 6E 00 00 }

	condition:
		(( all of ($quasarstr*) or all of ($sql*)) and $resource) or all of ($net*)
}