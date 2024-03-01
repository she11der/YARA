rule BINARYALERT_Hacktool_Macos_Keylogger_Logkext
{
	meta:
		description = "LogKext is an open source keylogger for Mac OS X, a product of FSB software."
		author = "@mimeframe"
		id = "2e4ad9d0-5780-5a28-a76d-baac401b0648"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/SlEePlEs5/logKext"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_keylogger_logkext.yara#L1-L25"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "f0e3a7ea8ec4568c319e44f00d71fb368948b6fe08bdf86de4b33f0d2bafbb44"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "logKextPassKey" wide ascii
		$a2 = "Couldn't get system keychain:" wide ascii
		$a3 = "Error finding secret in keychain" wide ascii
		$a4 = "com_fsb_iokit_logKext" wide ascii
		$b1 = "logKext Password:" wide ascii
		$b2 = "Logging controls whether the daemon is logging keystrokes (default is on)." wide ascii
		$c1 = "logKextPassKey" wide ascii
		$c2 = "Error: couldn't create secAccess" wide ascii
		$d1 = "IOHIKeyboard" wide ascii
		$d2 = "Clear keyboards called with kextkeys" wide ascii
		$d3 = "Added notification for keyboard" wide ascii

	condition:
		3 of ($a*) or all of ($b*) or all of ($c*) or all of ($d*)
}
