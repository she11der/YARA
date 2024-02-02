rule BINARYALERT_Hacktool_Macos_Manwhoami_Mmetokendecrypt
{
	meta:
		description = "This program decrypts / extracts all authorization tokens on macOS / OS X / OSX."
		author = "@mimeframe"
		id = "2dc01ff3-4c4a-548d-b2f0-b36897ad6a5c"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/manwhoami/MMeTokenDecrypt"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_manwhoami_mmetokendecrypt.yara#L1-L15"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "ccfedfbff0c6eefe41e80fe488d4cae928a33e7b86019c6ec54d1c9005b35147"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "security find-generic-password -ws 'iCloud'" wide ascii
		$a2 = "ERROR getting iCloud Decryption Key" wide ascii
		$a3 = "Could not find MMeTokenFile. You can specify the file manually." wide ascii
		$a4 = "Decrypting token plist ->" wide ascii
		$a5 = "Successfully decrypted token plist!" wide ascii

	condition:
		3 of ($a*)
}