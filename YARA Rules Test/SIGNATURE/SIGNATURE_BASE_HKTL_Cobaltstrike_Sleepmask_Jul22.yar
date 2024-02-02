rule SIGNATURE_BASE_HKTL_Cobaltstrike_Sleepmask_Jul22
{
	meta:
		description = "Detects static bytes in Cobalt Strike 4.5 sleep mask function that are not obfuscated"
		author = "CodeX"
		id = "d396ab0e-b584-5a7c-8627-5f318a20f9dd"
		date = "2022-07-04"
		modified = "2023-12-05"
		reference = "https://codex-7.gitbook.io/codexs-terminal-window/blue-team/detecting-cobalt-strike/sleep-mask-kit-iocs"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_cobaltstrike.yar#L3-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "233b3cb441f45f400c0261589aac31dd1fcd9c4e3a86a6aaa46c60849063b34b"
		score = 80
		quality = 85
		tags = ""

	strings:
		$sleep_mask = { 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 45 33 DB 45 33 D2 33 FF 33 F6 48 8B E9 BB 03 00 00 00 85 D2 0F 84 81 00 00 00 0F B6 45 }

	condition:
		$sleep_mask
}