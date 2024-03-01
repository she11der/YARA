rule SBOUSSEADEN_Hunt_Credaccess_Cloud_Base64
{
	meta:
		description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
		author = "SBousseaden"
		id = "34460cb1-acf4-53e7-9c95-f69824a87836"
		date = "2020-07-20"
		modified = "2020-12-28"
		reference = "https://github.com/sbousseaden/YaraHunts/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L170-L186"
		license_url = "N/A"
		logic_hash = "bf0acdc6e72e3528a93709b99f40aa13b45d9a3d22d8373d54414cc9be49d4d0"
		score = 50
		quality = 75
		tags = ""

	strings:
		$aws = "\\.aws\\credentials" base64
		$gcloud1 = "\\gcloud\\credentials.db" base64
		$gcloud2 = "\\gcloud\\legacy_credentials" base64
		$gcloud3 = "\\gcloud\\access_tokens.db" base64
		$azure1 = "\\.azure\\accessTokens.json" base64
		$azure2 = "\\.azure\\azureProfile.json" base64
		$git = "\\.config\\git\\credentials" base64
		$slack1 = "\\Slack\\Cookies" base64
		$slack2 = "\\Slack\\StaleCookies-8" base64

	condition:
		4 of them
}
