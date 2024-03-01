rule ELASTIC_Linux_Hacktool_Earthworm_E3Da43E2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Earthworm (Linux.Hacktool.Earthworm)"
		author = "Elastic Security"
		id = "e3da43e2-1737-4c51-af6c-7c64d9cbfb07"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Hacktool_Earthworm.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "da0cffc4222d11825778fe4fa985fef2945caa0cc3b4de26af0a06509ebafb21"
		logic_hash = "b129b7060b6af4ff2aae2678a455b969579132891fba44e4fdc2481a5437bdf9"
		score = 60
		quality = 45
		tags = "FILE, MEMORY"
		fingerprint = "fdf19096c6afc1c3be75fe4bb2935aca8ac915c97ad0ab3c2b87e803347cc460"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8D 20 FF FF FF 4C 89 C1 4C 8B 85 20 FF FF FF 49 D3 E0 4C 21 C7 48 83 }

	condition:
		all of them
}
