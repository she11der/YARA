rule SIGNATURE_BASE_LNK_Malicious_Nov1 : FILE
{
	meta:
		description = "Detects a suspicious LNK file"
		author = "Florian Roth (Nextron Systems)"
		id = "1d08ac78-6ff0-5e3f-acc2-91bd63267d4c"
		date = "2017-11-06"
		modified = "2023-12-05"
		reference = "https://www.virustotal.com/en/file/ee069edc46a18698fa99b6d2204895e6a516af1a306ea986a798b178f289ecd6/analysis/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_mal_link.yar#L2-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a1aa29497a0e4741807e3d74d54be69061aed21524c5f901615bd21e2ef13c67"
		score = 60
		quality = 81
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$c1 = "C:\\Windows\\System32\\cmd.exe" ascii wide
		$s1 = "cmd.exe /" ascii wide nocase
		$s2 = { 00 25 00 53 00 79 00 73 00 74 00 65 00 6D 00 52
              00 6F 00 6F 00 74 00 25 00 5C 00 53 00 79 00 73
              00 74 00 65 00 6D 00 33 00 32 00 EF 01 2F 00 43
              00 20 00 22 00 63 00 6D 00 64 00 2E 00 65 00 78
              00 65 }
		$s3 = "%comspec%" ascii wide nocase fullword
		$fp1 = "Microsoft Visual" ascii wide

	condition:
		( uint32(0)==0x0000004c and filesize <4KB and $c1 and 1 of ($s*)) and not 1 of ($fp*)
}
