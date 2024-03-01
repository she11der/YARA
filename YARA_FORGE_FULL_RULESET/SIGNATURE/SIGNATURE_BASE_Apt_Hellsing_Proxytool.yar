rule SIGNATURE_BASE_Apt_Hellsing_Proxytool : FILE
{
	meta:
		description = "detection for Hellsing proxy testing tool"
		author = "Kaspersky Lab"
		id = "54454f07-11a9-5456-b489-9a9610e53123"
		date = "2015-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_hellsing_kaspersky.yar#L56-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8f2656e7b4e6fb5336fb4e39bcec3e99531db532f757b65e3aa12cd2a4334840"
		score = 50
		quality = 85
		tags = "FILE"
		version = "1.0"
		filetype = "PE"

	strings:
		$a1 = "PROXY_INFO: automatic proxy url => %s"
		$a2 = "PROXY_INFO: connection type => %d"
		$a3 = "PROXY_INFO: proxy server => %s"
		$a4 = "PROXY_INFO: bypass list => %s"
		$a5 = "InternetQueryOption failed with GetLastError() %d"
		$a6 = "D:\\Hellsing\\release\\exe\\exe\\" nocase

	condition:
		uint16(0)==0x5a4d and (2 of ($a*)) and filesize <300000
}
