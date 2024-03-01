rule DELIVRTO_SUSP_Onenote_Repeated_Filedatareference_Feb23 : FILE
{
	meta:
		description = "Repeated references to files embedded in OneNote file. May indicate multiple copies of file hidden under image, as leveraged by Qakbot et al."
		author = "delivr.to"
		id = "2a46d6cc-2800-5645-889c-7ad7d7aa69bd"
		date = "2023-02-17"
		modified = "2023-02-17"
		reference = "https://github.com/delivr-to/detections"
		source_url = "https://github.com/delivr-to/detections/blob/18dd1ea0660124e4949f15613c1bcc993d41194b/yara-rules/onenote_repeated_files.yar#L1-L23"
		license_url = "N/A"
		logic_hash = "ef74a128de4d3745af856957931eaae0c0ae5a5583eab1a7c58d6dd666e7fd15"
		score = 60
		quality = 80
		tags = "FILE"

	strings:
		$one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
		$fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }
		$fref = { 3C 00 69 00 66 00 6E 00 64 00 66 00 3E 00 7B 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? }

	condition:
		filesize <5MB and ($one at 0) and $fdso and #fref>(#fdso*4)
}
