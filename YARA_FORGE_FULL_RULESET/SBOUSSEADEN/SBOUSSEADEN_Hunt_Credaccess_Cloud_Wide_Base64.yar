rule SBOUSSEADEN_Hunt_Credaccess_Cloud_Wide_Base64
{
	meta:
		description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
		author = "SBousseaden"
		id = "5c9a77b6-612b-5d5d-926c-833e49f8020e"
		date = "2020-07-20"
		modified = "2020-12-28"
		reference = "https://github.com/sbousseaden/YaraHunts/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L188-L204"
		license_url = "N/A"
		logic_hash = "1dd7aba89ddef2d18807bef77abd106a74f2e339e1e3bbd102c2edee14ffcf6f"
		score = 50
		quality = 75
		tags = ""

	strings:
		$aws = "\\.aws\\credentials" wide base64
		$gcloud1 = "\\gcloud\\credentials.db" wide base64
		$gcloud2 = "\\gcloud\\legacy_credentials" wide base64
		$gcloud3 = "\\gcloud\\access_tokens.db" wide base64
		$azure1 = "\\.azure\\accessTokens.json" wide base64
		$azure2 = "\\.azure\\azureProfile.json" wide base64
		$git = "\\.config\\git\\credentials" wide base64
		$slack1 = "\\Slack\\Cookies" wide base64
		$slack2 = "\\Slack\\StaleCookies-8" wide base64

	condition:
		4 of them
}
