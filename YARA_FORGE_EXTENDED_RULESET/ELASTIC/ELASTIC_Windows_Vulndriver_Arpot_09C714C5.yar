rule ELASTIC_Windows_Vulndriver_Arpot_09C714C5 : FILE
{
	meta:
		description = "Name: aswArPot.sys, Version: 21.1.187.0"
		author = "Elastic Security"
		id = "09c714c5-7639-44cf-990f-16ac0d42f8f9"
		date = "2022-04-27"
		modified = "2022-05-03"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_VulnDriver_ArPot.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "4b5229b3250c8c08b98cb710d6c056144271de099a57ae09f5d2097fc41bd4f1"
		logic_hash = "e5f972ad9a31aefbd20237e6ea3dd19a025c2e3487fa080e9f9b8acf1e3f58e6"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "7876556bbfd68903a38103ccd6e9ec8c4c9a89e7dfaada86b6633a8d7ec9b806"
		threat_name = "Windows.VulnDriver.ArPot"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x15][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\xbb][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x14][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x15][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x15][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xba][\x00-\x00]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}