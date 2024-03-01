rule DELIVRTO_SUSP_Msg_CVE_2023_23397_Mar23 : CVE_2023_23397 FILE
{
	meta:
		description = "MSG file with a PidLidReminderFileParameter property, potentially exploiting CVE-2023-23397"
		author = "delivr.to"
		id = "a0ede2d3-7789-5662-9575-5d0a5cf4457c"
		date = "2023-03-15"
		modified = "2023-03-15"
		reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
		source_url = "https://github.com/delivr-to/detections/blob/e6b54cfab6326caa583f0506233698fc1e3a9ced/yara-rules/msg_cve_2023_23397.yar#L1-L20"
		license_url = "N/A"
		logic_hash = "0476cf7f93c4f6cc48c19933f31360b62fe5e339f6a2a31dee8ad95f83ce67d7"
		score = 60
		quality = 80
		tags = "CVE-2023-23397, FILE"

	strings:
		$app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$rfp = { 1F 85 00 00 }

	condition:
		uint32be(0)==0xD0CF11E0 and uint32be(4)==0xA1B11AE1 and $app and $rfp
}
