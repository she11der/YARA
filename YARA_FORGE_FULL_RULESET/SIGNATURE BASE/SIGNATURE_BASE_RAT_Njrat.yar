rule SIGNATURE_BASE_RAT_Njrat
{
	meta:
		description = "Detects njRAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "6289b9c8-eef6-5cfb-97bd-b819158d6fdd"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/njRat"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L1013-L1036"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "47e8cc71caaefd70a170eb8fc845cb7ddb8df04b90163fe35f1ccb9a3f614c57"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$s1 = {7C 00 27 00 7C 00 27 00 7C}
		$s2 = "netsh firewall add allowedprogram" wide
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s4 = "yyyy-MM-dd" wide
		$v1 = "cmd.exe /k ping 0 & del" wide
		$v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
		$v3 = "cmd.exe /c ping 0 -n 2 & del" wide

	condition:
		all of ($s*) and any of ($v*)
}
