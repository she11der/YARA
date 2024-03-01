rule ELASTIC_Windows_Trojan_Trickbot_5574Be7D : FILE MEMORY
{
	meta:
		description = "Targets injectDll64 containing injection functionality to steal banking credentials"
		author = "Elastic Security"
		id = "5574be7d-7502-4357-8110-2fb4a661b2bd"
		date = "2021-03-29"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Trickbot.yar#L398-L432"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "8c5c0d27153f60ef8aec57def2f88e3d5f9a7385b5e8b8177bab55fa7fac7b18"
		logic_hash = "ed0fc98c5d628ce38b923e1410eaf7a4a65ecffea42bed35314e30c99a52219b"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "23d9b89917a0fc5aad903595b89b650f6dbb0f82ce28ce8bcc891904f62ccf1b"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "webinject64.dll" ascii fullword
		$a2 = "Mozilla Firefox version: %s" ascii fullword
		$a3 = "socks=127.0.0.1:" ascii fullword
		$a4 = "<conf ctl=\"dpost\" file=\"dpost\" period=\"60\"/>" ascii fullword
		$a5 = "<moduleconfig>" ascii fullword
		$a6 = "https://%.*s%.*s" ascii fullword
		$a7 = "http://%.*s%.*s" ascii fullword
		$a8 = "Chrome version: %s" ascii fullword
		$a9 = "IE version real: %s" ascii fullword
		$a10 = "IE version old: %s" ascii fullword
		$a11 = "Build date: %s %s" ascii fullword
		$a12 = "EnumDpostServer" ascii fullword
		$a13 = "ESTR_PASS_" ascii fullword
		$a14 = "<conf ctl=\"dinj\" file=\"dinj\" period=\"20\"/>" ascii fullword
		$a15 = "<conf ctl=\"sinj\" file=\"sinj\" period=\"20\"/>" ascii fullword
		$a16 = "<autoconf>" ascii fullword

	condition:
		4 of ($a*)
}
