rule ELASTIC_Linux_Worm_Generic_98Efcd38 : FILE MEMORY
{
	meta:
		description = "Detects Linux Worm Generic (Linux.Worm.Generic)"
		author = "Elastic Security"
		id = "98efcd38-d579-46f7-a8f8-360f799a5078"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Worm_Generic.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "87507f5cd73fffdb264d76db9b75f30fe21cc113bcf82c524c5386b5a380d4bb"
		logic_hash = "c1a130d2ef8d09cb28adc4e347cbd1a083c78241752ecf3f935b03d774d00a81"
		score = 60
		quality = 25
		tags = "FILE, MEMORY"
		fingerprint = "d6cec73bb6093dbc6d26566c174d0d0f6448f431429edef0528c9ec1c83177fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 14 75 E1 8B 5A 24 01 EB 66 8B 0C 4B 8B 5A 1C 01 EB 8B 04 8B }

	condition:
		all of them
}
