rule BINARYALERT_Hacktool_Macos_Manwhoami_Icloudcontacts
{
	meta:
		description = "Pulls iCloud Contacts for an account. No dependencies. No user notification."
		author = "@mimeframe"
		id = "b6595540-7f89-5764-b34e-d32c1a377b6c"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/manwhoami/iCloudContacts"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_manwhoami_icloudcontacts.yara#L1-L14"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "0c5b81454b26de91f5ad126b24f10397e1da5d8561b0bf22c5df128753df0ac2"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "https://setup.icloud.com/setup/authenticate/" wide ascii
		$a2 = "https://p04-contacts.icloud.com/" wide ascii
		$a3 = "HTTP Error 401: Unauthorized. Are you sure the credentials are correct?" wide ascii
		$a4 = "HTTP Error 404: URL not found. Did you enter a username?" wide ascii

	condition:
		3 of ($a*)
}
