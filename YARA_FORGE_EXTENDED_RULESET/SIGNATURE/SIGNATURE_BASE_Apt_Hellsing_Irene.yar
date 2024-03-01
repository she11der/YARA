rule SIGNATURE_BASE_Apt_Hellsing_Irene : FILE
{
	meta:
		description = "detection for Hellsing msger irene installer"
		author = "Kaspersky Lab"
		id = "b57d1a10-4e5c-511f-b98c-8ce7d766c227"
		date = "2015-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_hellsing_kaspersky.yar#L119-L137"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e7da04083468dba7045b55181642d7cd57d543fbeda24685ba2ac63799740798"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"
		filetype = "PE"

	strings:
		$a1 = "\\Drivers\\usbmgr.tmp" wide
		$a2 = "\\Drivers\\usbmgr.sys" wide
		$a3 = "common_loadDriver CreateFile error!"
		$a4 = "common_loadDriver StartService error && GetLastError():%d!"
		$a5 = "irene" wide
		$a6 = "aPLib v0.43 - the smaller the better"

	condition:
		uint16(0)==0x5a4d and (4 of ($a*)) and filesize <500000
}
