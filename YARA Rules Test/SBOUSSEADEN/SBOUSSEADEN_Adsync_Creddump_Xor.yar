rule SBOUSSEADEN_Adsync_Creddump_Xor
{
	meta:
		description = "Azure AdSync Service Account Password Dumping"
		author = "SBousseaden"
		id = "e0d951ec-ec39-5f37-b5a8-ddd0b1dc588d"
		date = "2020-03-08"
		modified = "2020-12-28"
		reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L69-L89"
		license_url = "N/A"
		logic_hash = "831ed0410000ad9dfa7be2ab1f64a4130810465cf699bb3e45c93075db6fdb74"
		score = 75
		quality = 75
		tags = ""

	strings:
		$a1 = "private_configuration_xml" xor
		$a2 = "LoadKeySet" xor
		$a3 = "encrypted_configuration" xor
		$a4 = "GetActiveCredentialKey" xor
		$a5 = "DecryptBase64ToString" xor
		$a6 = "Cryptography.KeyManager" xor
		$b1 = "mms_management_agent" xor
		$b2 = "Microsoft Azure AD Sync\\Bin\\mcrypt.dl" xor
		$b3 = "xp_cmdshell" xor
		$b4 = "Password" xor
		$b5 = "forest-login-user" xor
		$b6 = "forest-login-domain" xor

	condition:
		4 of ($a*) or 4 of ($b*)
}