rule DELIVRTO_SUSP_Onenote_RTLO_Character_Feb23 : FILE
{
	meta:
		description = "Presence of RTLO Unicode Character in a OneNote file with embedded files"
		author = "delivr.to"
		id = "03d86391-1392-5734-af5f-8a2c7b99167a"
		date = "2023-02-17"
		modified = "2023-02-17"
		reference = "https://github.com/delivr-to/detections"
		source_url = "https://github.com/delivr-to/detections/blob/e6b54cfab6326caa583f0506233698fc1e3a9ced/yara-rules/onenote_rtlo_filename.yar#L1-L22"
		license_url = "N/A"
		logic_hash = "286bc1ab1f5df0d64634f53cc82357187306c40b063b156f36b602e131262c7a"
		score = 60
		quality = 55
		tags = "FILE"

	strings:
		$one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
		$fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }
		$rtlo = { 00 2E 20 }

	condition:
		filesize <5MB and ($one at 0) and $fdso and $rtlo
}
