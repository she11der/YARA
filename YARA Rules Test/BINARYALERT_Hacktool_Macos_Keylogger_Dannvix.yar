rule BINARYALERT_Hacktool_Macos_Keylogger_Dannvix
{
	meta:
		description = "A simple keylogger for macOS."
		author = "@mimeframe"
		id = "598d6dbc-540d-5f96-8bd1-c15e6194012e"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/dannvix/keylogger-osx"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_keylogger_dannvix.yara#L1-L13"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "95d0540b1308caf3e7287c70a759954650220192800c0154d225bcb01ed55766"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "/var/log/keystroke.log" wide ascii
		$a2 = "<forward-delete>" wide ascii
		$a3 = "<unknown>" wide ascii

	condition:
		all of ($a*)
}