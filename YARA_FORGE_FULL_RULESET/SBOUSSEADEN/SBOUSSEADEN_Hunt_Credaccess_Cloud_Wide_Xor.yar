rule SBOUSSEADEN_Hunt_Credaccess_Cloud_Wide_Xor
{
	meta:
		description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
		author = "SBousseaden"
		id = "8e48151c-8a9b-57b1-8464-5be28afc347b"
		date = "2020-07-20"
		modified = "2020-12-28"
		reference = "https://github.com/sbousseaden/YaraHunts/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L152-L168"
		license_url = "N/A"
		logic_hash = "0625fc019eeeac8c219fa997c5957b69e5073c82d5cb1b880a5c1f7295ba2b7a"
		score = 50
		quality = 75
		tags = ""

	strings:
		$aws = "\\.aws\\credentials" wide xor
		$gcloud1 = "\\gcloud\\credentials.db" wide xor
		$gcloud2 = "\\gcloud\\legacy_credentials" wide xor
		$gcloud3 = "\\gcloud\\access_tokens.db" wide xor
		$azure1 = "\\.azure\\accessTokens.json" wide xor
		$azure2 = "\\.azure\\azureProfile.json" wide xor
		$git = "\\.config\\git\\credentials" wide xor
		$slack1 = "\\Slack\\Cookies" wide xor
		$slack2 = "\\Slack\\StaleCookies-8" wide xor

	condition:
		4 of them
}
