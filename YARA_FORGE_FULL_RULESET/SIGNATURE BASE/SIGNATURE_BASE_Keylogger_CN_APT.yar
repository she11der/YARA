rule SIGNATURE_BASE_Keylogger_CN_APT : FILE
{
	meta:
		description = "Keylogger - generic rule for a Chinese variant"
		author = "Florian Roth (Nextron Systems)"
		id = "7be0b175-05a4-5725-ba21-9438c0fcd740"
		date = "2016-03-07"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_keylogger_cn.yar#L8-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3efb3b5be39489f19d83af869f11a8ef8e9a09c3c7c0ad84da31fc45afcf06e7"
		logic_hash = "a5330d15ad7199212cec44ade401c224c40a468650abbc7bf282b26a21cdc22b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "Mozilla/4.0 (compatible; MSIE6.0;Windows NT 5.1)" fullword ascii
		$x2 = "attrib -s -h -r c:\\ntldr" fullword ascii
		$x3 = "%sWindows NT %d.%d" fullword ascii
		$x4 = "Referer: http://%s/%s.aspx?n=" fullword ascii
		$s1 = "\\cmd.exe /c \"systeminfo.exe >> " fullword ascii
		$s2 = "%s\\cmd.exe /c %s >> \"%s\"" fullword ascii
		$s3 = "shutdown.exe -r -t 0" fullword ascii
		$s4 = "dir \"%SystemDrive%\\\" /s /a" fullword ascii
		$s5 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;" fullword ascii
		$s6 = "http_s.exe" fullword ascii
		$s7 = "User Agent\\Post Platform\\" ascii
		$s8 = "desktop.tmp" fullword ascii
		$s9 = "\\support.icw" ascii
		$s10 = "agc.tmp" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of ($x*)) or 3 of them
}
