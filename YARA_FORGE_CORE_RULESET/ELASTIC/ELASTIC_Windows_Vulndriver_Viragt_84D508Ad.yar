rule ELASTIC_Windows_Vulndriver_Viragt_84D508Ad : FILE
{
	meta:
		description = "Name: viragt64.sys, Version: 1.0.0.11"
		author = "Elastic Security"
		id = "84d508ad-939d-4e3b-b9a6-204eb8bcaee5"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/yara/rules/Windows_VulnDriver_Viragt.yar#L23-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/LICENSE.txt"
		hash = "58a74dceb2022cd8a358b92acd1b48a5e01c524c3b0195d7033e4bd55eff4495"
		logic_hash = "a3e1b41155c7dd347976a1057cb763ab60c50c34e981fef050bd54f060a412fc"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "172be67b6bb07f189fd5e535e173d245114bf4b17c3daf89924a30c7219d3e69"
		threat_name = "Windows.VulnDriver.Viragt"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 76 00 69 00 72 00 61 00 67 00 74 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x0b][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}
