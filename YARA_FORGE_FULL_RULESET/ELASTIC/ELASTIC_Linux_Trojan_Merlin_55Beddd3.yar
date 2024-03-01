rule ELASTIC_Linux_Trojan_Merlin_55Beddd3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Merlin (Linux.Trojan.Merlin)"
		author = "Elastic Security"
		id = "55beddd3-735b-4e0c-a387-e6a981cd42a3"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Trojan_Merlin.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "15ccdf2b948fe6bd3d3a7f5370e72cf3badec83f0ec7f47cdf116990fb551adf"
		logic_hash = "293158c981463544abd0c38694bfc8635ad1a679bbae115521b65879f145cea6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "54e03337930d74568a91e797cfda3b7bfbce3aad29be2543ed58c51728d8e185"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { AF F0 4C 01 F1 4C 8B B4 24 A8 00 00 00 4D 0F AF F4 4C 01 F1 4C 8B B4 24 B0 00 }

	condition:
		all of them
}
