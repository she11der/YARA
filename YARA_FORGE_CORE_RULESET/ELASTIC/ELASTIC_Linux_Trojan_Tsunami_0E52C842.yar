rule ELASTIC_Linux_Trojan_Tsunami_0E52C842 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "0e52c842-f65e-4c77-8081-ae2f160e35f4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/yara/rules/Linux_Trojan_Tsunami.yar#L360-L378"
		license_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/LICENSE.txt"
		hash = "cf1ca1d824c8687e87a5b0275a0e39fa101442b4bbf470859ddda9982f9b3417"
		logic_hash = "35046c6686ee7239844e2fbd092b4ab91a1c22606062fb0031bdb28bfa2c9827"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "70fdfb7aa5d1eff98e4e216e7a60ed1ba4d75ed1f47a57bf40eeaf35a92c88e4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 55 48 89 E5 53 48 83 EC 38 89 7D E4 48 89 75 D8 89 55 D4 48 89 }

	condition:
		all of them
}
