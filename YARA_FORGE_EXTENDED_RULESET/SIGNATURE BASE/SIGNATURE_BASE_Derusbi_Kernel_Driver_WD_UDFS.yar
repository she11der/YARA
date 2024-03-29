rule SIGNATURE_BASE_Derusbi_Kernel_Driver_WD_UDFS : FILE
{
	meta:
		description = "Detects Derusbi Kernel Driver"
		author = "Florian Roth (Nextron Systems)"
		id = "51d80d19-f87f-5b09-ac49-08ebcb464013"
		date = "2015-12-15"
		modified = "2023-12-05"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_derusbi.yar#L48-L79"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "bea8dafbef01ca8cf747a1f24804c0fb7868db09ce8091ff93c9c5d67d95ca3e"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1b449121300b0188ff9f6a8c399fb818d0cf53fd36cf012e6908a2665a27f016"
		hash2 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
		hash3 = "6cdb65dbfb2c236b6d149fd9836cb484d0608ea082cf5bd88edde31ad11a0d58"
		hash4 = "e27fb16dce7fff714f4b05f2cef53e1919a34d7ec0e595f2eaa155861a213e59"

	strings:
		$x1 = "\\\\.\\pipe\\usbpcex%d" fullword wide
		$x2 = "\\\\.\\pipe\\usbpcg%d" fullword wide
		$x3 = "\\??\\pipe\\usbpcex%d" fullword wide
		$x4 = "\\??\\pipe\\usbpcg%d" fullword wide
		$x5 = "$$$--Hello" fullword ascii
		$x6 = "Wrod--$$$" fullword ascii
		$s1 = "\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" wide
		$s2 = "Update.dll" fullword ascii
		$s3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI" wide
		$s4 = "\\Driver\\nsiproxy" wide
		$s5 = "HOST: %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <800KB and (2 of ($x*) or all of ($s*))
}
