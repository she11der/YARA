rule BINARYALERT_Hacktool_Macos_Keylogger_Skreweverything_Swift
{
	meta:
		description = "It is a simple and easy to use keylogger for macOS written in Swift."
		author = "@mimeframe"
		id = "a4918bc3-d3f0-59f4-894f-fd34ee944fac"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/SkrewEverything/Swift-Keylogger"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_keylogger_skreweverything_swift.yara#L1-L15"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "f400b8ec392417e7443e82a2c2a9adfc868b9795aa1fb29f91d228f6f94efd13"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "Can't create directories!" wide ascii
		$a2 = "Can't create manager" wide ascii
		$a3 = "Can't open HID!" wide ascii
		$a4 = "PRINTSCREEN" wide ascii
		$a5 = "LEFTARROW" wide ascii

	condition:
		4 of ($a*)
}
