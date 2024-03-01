rule SIGNATURE_BASE_Blackenergy_VBS_Agent : FILE
{
	meta:
		description = "Detects VBS Agent from BlackEnergy Report - file Dropbearrun.vbs"
		author = "Florian Roth (Nextron Systems)"
		id = "0876f752-d476-5706-918e-edfda9bd7928"
		date = "2016-01-03"
		modified = "2023-12-05"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_blackenergy.yar#L34-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b90f268b5e7f70af1687d9825c09df15908ad3a6978b328dc88f96143a64af0f"
		logic_hash = "2a0037a76f1031117fe41b2e41691511eb626ffc0c738547eda24f771505bc67"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "WshShell.Run \"dropbear.exe -r rsa -d dss -a -p 6789\", 0, false" fullword ascii
		$s1 = "WshShell.CurrentDirectory = \"C:\\WINDOWS\\TEMP\\Dropbear\\\"" fullword ascii
		$s2 = "Set WshShell = CreateObject(\"WScript.Shell\")" fullword ascii

	condition:
		filesize <1KB and 2 of them
}
