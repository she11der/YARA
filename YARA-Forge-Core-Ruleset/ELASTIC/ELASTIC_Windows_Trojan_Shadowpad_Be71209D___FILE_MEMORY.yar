rule ELASTIC_Windows_Trojan_Shadowpad_Be71209D___FILE_MEMORY
{
	meta:
		description = "Target ShadowPad loader"
		author = "Elastic Security"
		id = "be71209d-b1c0-4922-87ae-47d0930d8755"
		date = "2023-01-31"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/yara/rules/Windows_Trojan_ShadowPad.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/LICENSE.txt"
		hash = "452b08d6d2aa673fb6ccc4af6cebdcb12b5df8722f4d70d1c3491479e7b39c05"
		logic_hash = "24e035bbcd5d44877e6e582a995d0035ad26c53e832c34b0c8a3836cb1a11637"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "629f1502ce9f429ba6d497b8f2b0b35e57ca928a764ee6f3cb43521bfa6b5af4"
		threat_name = "Windows.Trojan.ShadowPad"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "{%8.8x-%4.4x-%4.4x-%8.8x%8.8x}"

	condition:
		all of them
}