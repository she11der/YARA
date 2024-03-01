rule ELASTIC_Windows_Ransomware_Snake_0Cfc8Ef3 : beta FILE MEMORY
{
	meta:
		description = "Identifies SNAKE ransomware"
		author = "Elastic Security"
		id = "0cfc8ef3-d8cc-4fc0-9ca2-8e84dbcb45bd"
		date = "2020-06-30"
		modified = "2021-08-23"
		reference = "https://labs.sentinelone.com/new-snake-ransomware-adds-itself-to-the-increasing-collection-of-golang-crimeware/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/yara/rules/Windows_Ransomware_Snake.yar#L48-L68"
		license_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/LICENSE.txt"
		logic_hash = "63bea7198f1e880443112a1e99e6e9f18666241fe4fae627ecdb4fc191e47f71"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4dd2565c42d52f20b9787a6ede9be24837f6df19dfbbd4e58e5208894741ba26"
		threat_name = "Windows.Ransomware.Snake"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$d1 = { 96 88 44 2C 1E 96 45 }
		$d2 = { 39 C5 7D ?? 0F B6 34 2B 39 D5 73 ?? 0F B6 3C 29 31 FE 83 FD 1A 72 }

	condition:
		1 of ($d*)
}
