rule SBOUSSEADEN_Adsync_Creddump_Wide
{
	meta:
		description = "AD Connect Sync Credential Extract"
		author = "SBousseaden"
		id = "ccbfa79a-924b-512a-a9e9-005567b4fe83"
		date = "2020-04-08"
		modified = "2020-12-28"
		reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L45-L67"
		license_url = "N/A"
		logic_hash = "e8b0ff1fa9117a98799239d37c5a0ae8be25c2c2519c4fc2a1d7f085a9ebe2e1"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = "private_configuration_xml" wide xor
		$s2 = "LoadKeySet" xor
		$s3 = "encrypted_configuration" wide xor
		$s4 = "GetActiveCredentialKey" xor
		$s5 = "DecryptBase64ToString" xor
		$s6 = "KeyManager" xor
		$s7 = "(LocalDB)\\.\\ADSync" wide xor
		$s8 = "mms_management_agent" wide xor
		$s9 = "keyset_id" wide xor
		$s10 = "xp_cmdshell" xor
		$s11 = "System.Data.SqlClient"
		$s12 = "Password" wide xor
		$fp1 = "mmsutils\\mmsutils.pdb"

	condition:
		5 of them and not $fp1
}