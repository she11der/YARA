rule ELASTIC_Windows_Trojan_Downtown_145Ecd2F___FILE_MEMORY
{
	meta:
		description = "Detects Windows Trojan Downtown (Windows.Trojan.DownTown)"
		author = "Elastic Security"
		id = "145ecd2f-d012-4566-a2e9-696cdbd793ce"
		date = "2023-08-23"
		modified = "2023-09-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/yara/rules/Windows_Trojan_DownTown.yar#L22-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/LICENSE.txt"
		logic_hash = "744a51c5317e265177185d9d0b8838a8fc939b4c56cc5e5bc51d5432d046d9f1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d755ad4a24b390ce56d4905e40cec83a39ea515cfbe7e1a534950ca858343e70"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "DeletePluginObject"
		$a2 = "GetPluginInfomation"
		$a3 = "GetPluginObject"
		$a4 = "GetRegisterCode"

	condition:
		all of them
}