rule SIGNATURE_BASE_Setupbdoor
{
	meta:
		description = "Webshells Auto-generated - file SetupBDoor.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "055ff783-fa9f-5037-a3d6-88b58ec1612f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8931-L8942"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "41f89e20398368e742eda4a3b45716b6"
		logic_hash = "b4b6a0e4b9f8975d769d340a420af37dbc344d32c72447a8c56b05e985e6d806"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\BDoor\\SetupBDoor"

	condition:
		all of them
}
