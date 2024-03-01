rule ELASTIC_Linux_Hacktool_Earthworm_82D5C4Cf : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Earthworm (Linux.Hacktool.Earthworm)"
		author = "Elastic Security"
		id = "82d5c4cf-ab96-4644-b1f3-2e95f1b49e7c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Hacktool_Earthworm.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "dc412d4f2b0e9ca92063a47adfb0657507d3f2a54a415619db5a7ccb59afb204"
		logic_hash = "81f35293bd3dd0cfbbf67f036773e16625bb74e06320fa1fff5bc428ef2f3a43"
		score = 60
		quality = 45
		tags = "FILE, MEMORY"
		fingerprint = "400342ab702de1a7ec4dd7e9b415b8823512f74a9abe578f08f7d79265bef385"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 E5 48 83 EC 20 31 C0 89 C1 48 8D 55 F0 48 89 7D F8 48 8B }

	condition:
		all of them
}
