rule BINARYALERT_Hacktool_Macos_Keylogger_Eldeveloper_Keystats
{
	meta:
		description = "A simple keylogger for macOS."
		author = "@mimeframe"
		id = "7fddb502-ae2d-5e14-95f5-115498fa5926"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/ElDeveloper/keystats"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_keylogger_eldeveloper_keystats.yara#L1-L13"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "c73f5ca2ba0a1bde7c1f9b96173938e40511e12f875c4d850d6d498c63e89385"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "YVBKeyLoggerPerishedNotification" wide ascii
		$a2 = "YVBKeyLoggerPerishedByLackOfResponseNotification" wide ascii
		$a3 = "YVBKeyLoggerPerishedByUserChangeNotification" wide ascii

	condition:
		2 of ($a*)
}
