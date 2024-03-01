rule DELIVRTO_SUSP_ZPAQ_Archive_Nov23 : FILE
{
	meta:
		description = "ZPAQ file archive with expected file and block headers"
		author = "delivr.to"
		id = "28b6ffbe-be95-5ac8-ad3e-f9713a204d98"
		date = "2023-11-26"
		modified = "2023-11-27"
		reference = "https://www.gdatasoftware.com/blog/2023/11/37822-agent-tesla-zpaq"
		source_url = "https://github.com/delivr-to/detections/blob/e6b54cfab6326caa583f0506233698fc1e3a9ced/yara-rules/zpaq_archives.yar#L1-L14"
		license_url = "N/A"
		logic_hash = "348144ee7137def00b37e074507e8148e51d34c484802a56bcd6e090d4628f18"
		score = 40
		quality = 80
		tags = "FILE"

	strings:
		$fh = { 37 6B 53 74 A0 31 83 D3 8C B2 28 B0 D3 }
		$block_header = /jDC\d{14}[cdhi]\d{10}/

	condition:
		$fh at 0 and $block_header
}
