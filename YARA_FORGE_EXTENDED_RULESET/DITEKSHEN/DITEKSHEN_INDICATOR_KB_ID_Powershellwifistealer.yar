rule DITEKSHEN_INDICATOR_KB_ID_Powershellwifistealer
{
	meta:
		description = "Detects email accounts used for exfiltration observed in PowerShellWiFiStealer"
		author = "ditekShen"
		id = "fa19e422-c682-5464-b034-330942daf3bd"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L691-L704"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f119b54032e2a6ca35819e811e6479b00936115d98ef6e928f4c819d04a8321f"
		score = 75
		quality = 63
		tags = ""

	strings:
		$s1 = "hajdebebreidekreide@gmail.com" ascii wide nocase
		$s2 = "usb@pterobot.net" ascii wide nocase
		$s3 = "umairdadaber@gmail.com" ascii wide nocase
		$s4 = "mrumairok@gmail.com" ascii wide nocase
		$s5 = "credsenderbot@gmail.com" ascii wide nocase
		$s6 = "easywareytb@gmail.com" ascii wide nocase

	condition:
		any of them
}
