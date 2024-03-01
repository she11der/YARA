rule SIGNATURE_BASE_Peek_A_Boo
{
	meta:
		description = "Webshells Auto-generated - file peek-a-boo.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "f6ca33b5-e37f-5124-a193-a3056c559314"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8543-L8559"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "aca339f60d41fdcba83773be5d646776"
		logic_hash = "b103c1b873dd0df9626d72a1127fbadc821777a05012a080423263a2083c398b"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "__vbaHresultCheckObj"
		$s1 = "\\VB\\VB5.OLB"
		$s2 = "capGetDriverDescriptionA"
		$s3 = "__vbaExceptHandler"
		$s4 = "EVENT_SINK_Release"
		$s8 = "__vbaErrorOverflow"

	condition:
		all of them
}
