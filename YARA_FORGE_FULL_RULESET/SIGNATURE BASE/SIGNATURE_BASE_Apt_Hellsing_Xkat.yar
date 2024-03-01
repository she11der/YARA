rule SIGNATURE_BASE_Apt_Hellsing_Xkat : FILE
{
	meta:
		description = "detection for Hellsing xKat tool"
		author = "Kaspersky Lab"
		id = "c831ce04-8fb2-5790-8aaf-c88b370835ac"
		date = "2015-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_hellsing_kaspersky.yar#L76-L97"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ba74ca11c96e59a04f1cb57b4866df7a581ad94ca81230f2ca5068c8808297aa"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"
		filetype = "PE"

	strings:
		$a1 = "\\Dbgv.sys"
		$a2 = "XKAT_BIN"
		$a3 = "release sys file error."
		$a4 = "driver_load error. "
		$a5 = "driver_create error."
		$a6 = "delete file:%s error."
		$a7 = "delete file:%s ok."
		$a8 = "kill pid:%d error."
		$a9 = "kill pid:%d ok."
		$a10 = "-pid-delete"
		$a11 = "kill and delete pid:%d error."
		$a12 = "kill and delete pid:%d ok."

	condition:
		uint16(0)==0x5a4d and (6 of ($a*)) and filesize <300000
}
