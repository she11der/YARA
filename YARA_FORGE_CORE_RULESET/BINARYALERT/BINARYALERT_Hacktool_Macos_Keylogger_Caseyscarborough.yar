rule BINARYALERT_Hacktool_Macos_Keylogger_Caseyscarborough
{
	meta:
		description = "A simple and easy to use keylogger for macOS."
		author = "@mimeframe"
		id = "82d9ff7e-b475-5888-82e1-f65c286a9cde"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/caseyscarborough/keylogger"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_keylogger_caseyscarborough.yara#L1-L14"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "d97fbfefe027a26ec998743b811734e62423e8a5ba4e11d516dcfc9e4831d296"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "/var/log/keystroke.log" wide ascii
		$a2 = "ERROR: Unable to create event tap." wide ascii
		$a3 = "Keylogging has begun." wide ascii
		$a4 = "ERROR: Unable to open log file. Ensure that you have the proper permissions." wide ascii

	condition:
		2 of ($a*)
}
