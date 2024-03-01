rule SIGNATURE_BASE_Gen_Base64_EXE : HIGHVOL FILE
{
	meta:
		description = "Detects Base64 encoded Executable in Executable"
		author = "Florian Roth (Nextron Systems)"
		id = "ef919a63-9a29-5624-a084-b92e3578e3a6"
		date = "2017-04-21"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/general_cloaking.yar#L71-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6fe18ee727a836c0baaac4dbbffdb9f50065f56a4c6eeee7e54792a8a66229de"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" wide ascii
		$s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" wide ascii
		$s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" wide ascii
		$s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" wide ascii
		$s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii
		$fp1 = "BAM Management class library"

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and 1 of ($s*) and not 1 of ($fp*)
}
