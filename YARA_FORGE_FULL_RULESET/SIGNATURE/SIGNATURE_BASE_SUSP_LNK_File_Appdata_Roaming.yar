rule SIGNATURE_BASE_SUSP_LNK_File_Appdata_Roaming : FILE
{
	meta:
		description = "Detects a suspicious link file that references to AppData Roaming"
		author = "Florian Roth (Nextron Systems)"
		id = "d905e58f-ae2e-5dc2-b206-d0435b023df0"
		date = "2018-05-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_suspicious_strings.yar#L148-L168"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5e5c78d3fe3fcdbfb097f833fbb1e15ad1f79e63b330eaba754d8b5296b5165a"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "AppData" fullword wide
		$s3 = "Roaming" fullword wide
		$s4 = { 00 2E 00 65 00 78 00 65 00 2E 00 43 00 3A 00 5C
              00 55 00 73 00 65 00 72 00 73 00 5C }

	condition:
		uint16(0)==0x004c and uint32(4)==0x00021401 and ( filesize <1KB and all of them )
}
