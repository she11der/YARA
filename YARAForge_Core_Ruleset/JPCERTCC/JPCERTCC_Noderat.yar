rule JPCERTCC_Noderat
{
	meta:
		description = "detect Noderat in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "9c2c4b0f-0f45-54f6-a98c-b592af882eef"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://blogs.jpcert.or.jp/ja/2019/02/tick-activity.html"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L429-L442"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "e1254b6cf28161943db202ea0a6ff2d86aa7975d4a3ecc0f26eed58101e54960"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$config = "/config/app.json"
		$key = "/config/.regeditKey.rc"
		$message = "uninstall error when readFileSync: "

	condition:
		all of them
}