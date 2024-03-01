rule SBOUSSEADEN_Adsync_Creddump_Xwide
{
	meta:
		description = "Azure AdSync Service Account Password Dumping"
		author = "SBousseaden"
		id = "a8c3e60a-99b8-50c8-992c-fbe18499a615"
		date = "2020-03-08"
		modified = "2020-12-28"
		reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L112-L132"
		license_url = "N/A"
		logic_hash = "9015005494cb3cc52645a9c82f6179992942243a816b05273bc26f58ac70a2e0"
		score = 75
		quality = 75
		tags = ""

	strings:
		$a1 = "private_configuration_xml" wide xor
		$a2 = "LoadKeySet" wide xor
		$a3 = "encrypted_configuration" wide xor
		$a4 = "GetActiveCredentialKey" wide xor
		$a5 = "DecryptBase64ToString" wide xor
		$a6 = "Cryptography.KeyManager" wide xor
		$b1 = "mms_management_agent" wide xor
		$b2 = "Microsoft Azure AD Sync\\Bin\\mcrypt.dl" wide xor
		$b3 = "xp_cmdshell" wide xor
		$b4 = "Password" wide xor
		$b5 = "forest-login-user" wide xor
		$b6 = "forest-login-domain" wide xor

	condition:
		4 of ($a*) or 4 of ($b*)
}
