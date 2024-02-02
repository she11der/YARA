rule JPCERTCC_Netwire
{
	meta:
		description = "detect netwire in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "cf71b80f-2618-5209-bb49-fefea9e0a7f3"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L351-L367"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "fa6ec967b6b3de226dcdb06d6b8f684800331a2420f038dd6274a8b9c3d8be78"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$v1 = "HostId-%Rand%"
		$v2 = "mozsqlite3"
		$v3 = "[Scroll Lock]"
		$v4 = "GetRawInputData"
		$ping = "ping 192.0.2.2"
		$log = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"

	condition:
		($v1) or ($v2 and $v3 and $v4) or ($ping and $log)
}