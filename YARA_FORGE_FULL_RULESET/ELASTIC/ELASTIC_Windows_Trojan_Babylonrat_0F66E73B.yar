rule ELASTIC_Windows_Trojan_Babylonrat_0F66E73B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Babylonrat (Windows.Trojan.Babylonrat)"
		author = "Elastic Security"
		id = "0f66e73b-7824-46b6-a9e6-5abf018c9ffa"
		date = "2021-09-02"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Babylonrat.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "4278064ec50f87bb0471053c068b13955ed9d599434e687a64bf2060438a7511"
		logic_hash = "66223dc9e2ef7330e26c91f0c82c555e96e4c794a637ab2cbe36410f3eca202a"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "3998824e381f51aaa2c81c12d4c05157c642d8aef39982e35fa3e124191640ea"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "BabylonRAT" wide fullword
		$a2 = "Babylon RAT Client" wide fullword
		$a3 = "ping 0 & del \"" wide fullword
		$a4 = "\\%Y %m %d - %I %M %p" wide fullword

	condition:
		all of them
}
