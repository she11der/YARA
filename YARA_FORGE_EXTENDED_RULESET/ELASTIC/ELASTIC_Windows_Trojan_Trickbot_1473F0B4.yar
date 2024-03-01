rule ELASTIC_Windows_Trojan_Trickbot_1473F0B4 : FILE MEMORY
{
	meta:
		description = "Targets mailsearcher64.dll module"
		author = "Elastic Security"
		id = "1473f0b4-a6b5-4b19-a07e-83d32a7e44a0"
		date = "2021-03-29"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Trojan_Trickbot.yar#L434-L459"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "9cfb441eb5c60ab1c90b58d4878543ee554ada2cceee98d6b867e73490d30fec"
		logic_hash = "dc13625e58c029c60b8670f8e63cd7786bf3e9705c462f3cbbf5b39e7c02f9a1"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "15438ae141a2ac886b1ba406ba45119da1a616c3b2b88da3f432253421aa8e8b"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "mailsearcher.dll" ascii fullword
		$a2 = "%s/%s/%s/send/" wide fullword
		$a3 = "Content-Disposition: form-data; name=\"list\"" ascii fullword
		$a4 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autostart>no</autostart><autoconf><conf ctl=\"SetConf\" file=\"mail"
		$a5 = "eriod=\"60\"/></autoconf></moduleconfig>" ascii fullword
		$a6 = "=Waitu H" ascii fullword
		$a7 = "Content-Length: %d" ascii fullword

	condition:
		2 of ($a*)
}
