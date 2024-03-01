rule AVASTTI_Cobaltstrike_Strike_Payload_Xored
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "0e075644-e278-5c5b-bdcc-dc2d6a32ce73"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L595-L613"
		license_url = "N/A"
		logic_hash = "532cf38554ad7211fab74d050007f6fe8d63c20e05f21a6737fff12ac92a81d7"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { 10 ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? 61 61 61 61 }

	condition:
		uint32be(@h01+8)^ uint32be(@h01+16)==0xFCE88900 or uint32be(@h01+8)^ uint32be(@h01+16)==0xFC4883E4 or uint32be(@h01+8)^ uint32be(@h01+16)==0x4D5AE800 or uint32be(@h01+8)^ uint32be(@h01+16)==0x4D5A4152 or uint32be(@h01+8)^ uint32be(@h01+16)==0x90909090
}
