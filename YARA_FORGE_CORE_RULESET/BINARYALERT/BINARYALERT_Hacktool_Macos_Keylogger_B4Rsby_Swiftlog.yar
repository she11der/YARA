rule BINARYALERT_Hacktool_Macos_Keylogger_B4Rsby_Swiftlog
{
	meta:
		description = "Dirty user level command line keylogger hacked together in Swift."
		author = "@mimeframe"
		id = "b1ae8284-04a0-5818-9997-0e31eb51ed2b"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/b4rsby/SwiftLog"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_keylogger_b4rsby_swiftlog.yara#L1-L11"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "c66dcab2da0e543198f97ca104c13533c8950d10b6f7cbd3f906348d0f8c45ff"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "You need to enable the keylogger in the System Prefrences" wide ascii

	condition:
		all of ($a*)
}
