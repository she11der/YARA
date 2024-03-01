rule EMBEERESEARCH_Win_Redline_Payload_Dec_2023
{
	meta:
		description = "Patterns observed in redline"
		author = "Matthew @ Embee_Research"
		id = "6208779a-69b2-55b5-9744-987575c00d96"
		date = "2023-12-24"
		modified = "2023-12-29"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/d4226e586a49cd4d1eede9a58738509689cf059f/Rules/win_redline_payload_dec_2023.yar#L1-L16"
		license_url = "N/A"
		hash = "5790aead07ce0b9b508392b9a2f363ef77055ae16c44231773849c87a1dd15a4"
		logic_hash = "d016baa5017120a3037e9cef7fd649228f7be60e511ecbdedf97916f59eec881"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = {16 72 ?? ?? ?? 70 A2 7E ?? ?? ?? 04 17 72 ?? ?? ?? 70 7E ?? ?? ?? 04 16 9A 28 ?? ?? ?? 06 A2 7E ?? ?? ?? 04 18 72 ?? ?? ?? 70 }

	condition:
		all of them
}
