rule SBOUSSEADEN_Hunt_Credaccess_Cloud
{
	meta:
		description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
		author = "SBousseaden"
		id = "a1916a13-ba08-57b4-8615-5ff08986e128"
		date = "2020-07-20"
		modified = "2020-12-28"
		reference = "https://github.com/sbousseaden/YaraHunts/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L134-L150"
		license_url = "N/A"
		logic_hash = "09814a4bb118b5015936943c8585475fd88e0b49d08587fedeeb2c0b4d7ab979"
		score = 50
		quality = 75
		tags = ""

	strings:
		$aws = "\\.aws\\credentials" xor
		$gcloud1 = "\\gcloud\\credentials.db" xor
		$gcloud2 = "\\gcloud\\legacy_credentials" xor
		$gcloud3 = "\\gcloud\\access_tokens.db" xor
		$azure1 = "\\.azure\\accessTokens.json" xor
		$azure2 = "\\.azure\\azureProfile.json" xor
		$git = "\\.config\\git\\credentials" xor
		$slack1 = "\\Slack\\Cookies" xor
		$slack2 = "\\Slack\\StaleCookies-8" xor

	condition:
		4 of them
}
