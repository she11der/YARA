rule JPCERTCC_Hawkeye
{
	meta:
		description = "detect HawkEye in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "fc988aaf-bdac-5a53-a90c-d35d86285cd6"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L259-L272"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "45256e1e56de3934d2e57a7c036d49a0f56c25538ed7ad3eb7ee8efa7f549e98"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$hawkstr1 = "HawkEye Keylogger" wide
		$hawkstr2 = "Dear HawkEye Customers!" wide
		$hawkstr3 = "HawkEye Logger Details:" wide

	condition:
		all of them
}