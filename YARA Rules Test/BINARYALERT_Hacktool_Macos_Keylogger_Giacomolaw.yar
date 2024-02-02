rule BINARYALERT_Hacktool_Macos_Keylogger_Giacomolaw
{
	meta:
		description = "A simple keylogger for macOS."
		author = "@mimeframe"
		id = "81fcf792-a0a9-5b97-a71c-4c517a7b910c"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/GiacomoLaw/Keylogger"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_keylogger_giacomolaw.yara#L1-L13"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "45ca583c07b8593ed716306ae6f80eef1c3fc5652aed739454fa8007fae929b4"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "ERROR: Unable to access keystroke log file. Please make sure you have the correct permissions." wide ascii
		$a2 = "ERROR: Unable to create event tap." wide ascii
		$a3 = "Keystrokes are now being recorded" wide ascii

	condition:
		2 of ($a*)
}