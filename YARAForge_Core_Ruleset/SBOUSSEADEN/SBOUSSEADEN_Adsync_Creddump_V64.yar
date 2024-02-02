rule SBOUSSEADEN_Adsync_Creddump_V64
{
	meta:
		description = "Azure AdSync Service Account Password Dumping"
		author = "SBousseaden"
		id = "9f536ff2-95b6-5f93-8c6f-e3738d6404c7"
		date = "2020-03-08"
		modified = "2020-12-28"
		reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L91-L111"
		license_url = "N/A"
		logic_hash = "e2465fec6dd9384d5d7f31f1c0e7661f4fbd5e3f87a14abfcb9b0412985cb1d6"
		score = 75
		quality = 75
		tags = ""

	strings:
		$a1 = "private_configuration_xml" base64
		$a2 = "LoadKeySet" base64
		$a3 = "encrypted_configuration" base64
		$a4 = "GetActiveCredentialKey" base64
		$a5 = "DecryptBase64ToString" base64
		$a6 = "Cryptography.KeyManager" base64
		$b1 = "mms_management_agent" base64
		$b2 = "Microsoft Azure AD Sync\\Bin\\mcrypt.dl" base64
		$b3 = "xp_cmdshell" base64
		$b4 = "Password" base64
		$b5 = "forest-login-user" base64
		$b6 = "forest-login-domain" base64

	condition:
		4 of ($a*) or 4 of ($b*)
}