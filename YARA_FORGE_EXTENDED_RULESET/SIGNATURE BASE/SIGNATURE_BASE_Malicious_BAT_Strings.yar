rule SIGNATURE_BASE_Malicious_BAT_Strings : FILE
{
	meta:
		description = "Detects a string also used in Netwire RAT auxilliary"
		author = "Florian Roth (Nextron Systems)"
		id = "6e197d05-62eb-535d-8cd6-db8550e51588"
		date = "2018-01-05"
		modified = "2023-12-05"
		reference = "https://pastebin.com/8qaiyPxs"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_netwire_rat.yar#L47-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "1f39b3fd11e7450eb1eaddeeca60aa4970568efda6053029f85df42e2f9fdd6e"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "call :deleteSelf&exit /b"

	condition:
		filesize <600KB and 1 of them
}
