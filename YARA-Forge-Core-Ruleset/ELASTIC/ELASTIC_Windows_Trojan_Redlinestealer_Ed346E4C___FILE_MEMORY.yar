rule ELASTIC_Windows_Trojan_Redlinestealer_Ed346E4C___FILE_MEMORY
{
	meta:
		description = "Detects Windows Trojan Redlinestealer (Windows.Trojan.RedLineStealer)"
		author = "Elastic Security"
		id = "ed346e4c-7890-41ee-8648-f512682fe20e"
		date = "2022-02-17"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/yara/rules/Windows_Trojan_RedLineStealer.yar#L58-L76"
		license_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/LICENSE.txt"
		hash = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
		logic_hash = "7ccf281f72018fff35f6024aefa12e7f925c7e9d5f1209e57aea4c93090c4ef9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "834c13b2e0497787e552bb1318664496d286e7cf57b4661e5e07bf1cffe61b82"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 55 8B EC 8B 45 14 56 57 8B 7D 08 33 F6 89 47 0C 39 75 10 76 15 8B }

	condition:
		all of them
}