rule JPCERTCC_Redleaves
{
	meta:
		description = "detect RedLeaves in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "e17a85de-6a15-5de5-ba9e-03ac6d896d7d"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://blogs.jpcert.or.jp/en/2017/05/volatility-plugin-for-detecting-redleaves-malware.html"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L53-L66"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "c79815dd26070184688d43b336dc2be07df5e2236e60c8ecc42f5efec2cab190"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory block scan"
		hash1 = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481"

	strings:
		$v1 = "red_autumnal_leaves_dllmain.dll"
		$b1 = { FF FF 90 00 }

	condition:
		$v1 and $b1 at 0
}
