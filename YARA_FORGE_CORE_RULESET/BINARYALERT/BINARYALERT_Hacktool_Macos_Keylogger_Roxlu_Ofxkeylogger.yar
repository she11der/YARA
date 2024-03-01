rule BINARYALERT_Hacktool_Macos_Keylogger_Roxlu_Ofxkeylogger
{
	meta:
		description = "ofxKeylogger keylogger."
		author = "@mimeframe"
		id = "c0e00b76-9623-5709-b64b-0afe006eba60"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/roxlu/ofxKeylogger"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_keylogger_roxlu_ofxkeylogger.yara#L1-L13"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "6e2579a10327cc8f1799848b3bcbcd95733a31098faeb849df6ebf99f1ffe808"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "keylogger_init" wide ascii
		$a2 = "install_keylogger_hook function not found in dll." wide ascii
		$a3 = "keylogger_set_callback" wide ascii

	condition:
		all of ($a*)
}
