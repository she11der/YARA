rule SIGNATURE_BASE_MAL_Hawkeye_Keylogger_Gen_Dec18
{
	meta:
		description = "Detects HawkEye Keylogger Reborn"
		author = "Florian Roth (Nextron Systems)"
		id = "1d06f364-a4e2-5632-ad3a-d53a8cddf072"
		date = "2018-12-10"
		modified = "2023-12-05"
		reference = "https://twitter.com/James_inthe_box/status/1072116224652324870"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_hawkeye.yar#L20-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b850f02849030d9912b7571e33e969427ac8f721d2f288ae3ac3e971c4ee4263"
		score = 75
		quality = 85
		tags = ""
		hash1 = "b8693e015660d7bd791356b352789b43bf932793457d54beae351cf7a3de4dad"

	strings:
		$s1 = "HawkEye Keylogger" fullword wide
		$s2 = "_ScreenshotLogger" ascii
		$s3 = "_PasswordStealer" ascii

	condition:
		2 of them
}
