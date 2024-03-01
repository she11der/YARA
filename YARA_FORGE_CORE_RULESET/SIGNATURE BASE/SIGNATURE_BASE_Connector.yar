rule SIGNATURE_BASE_Connector
{
	meta:
		description = "Webshells Auto-generated - file connector.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "e46026bc-c570-5057-a132-5a459c959a69"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8585-L8597"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "3ba1827fca7be37c8296cd60be9dc884"
		logic_hash = "b8cadb7aa23a8cdef10e7b1eb05586d6c3e7c398958a80861b6f1ccd4edf1eca"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "If ( AttackID = BROADCAST_ATTACK )"
		$s4 = "Add UNIQUE ID for victims / zombies"

	condition:
		all of them
}
