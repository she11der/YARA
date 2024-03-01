rule ELASTIC_Windows_Vulndriver_Iqvw_B8B45E6B : FILE
{
	meta:
		description = "Name: iQVW64.SYS, Version: 1.4.0.0"
		author = "Elastic Security"
		id = "b8b45e6b-9729-4e0e-ad08-488e1a4306e0"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_VulnDriver_Iqvw.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "37c637a74bf20d7630281581a8fae124200920df11ad7cd68c14c26cc12c5ec9"
		logic_hash = "b0a8716f550ba231ca7db61bafd6effbc351faa45864f9ebf7be81f63f14a933"
		score = 60
		quality = 55
		tags = "FILE"
		fingerprint = "eeabf1c506ac6db4de3279a8b03d676f95c6d93dad6ae0173f2adec2dae41b95"
		threat_name = "Windows.VulnDriver.Iqvw"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 51 00 56 00 57 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x04][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x03][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}
