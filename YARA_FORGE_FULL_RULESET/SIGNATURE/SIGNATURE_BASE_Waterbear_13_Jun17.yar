rule SIGNATURE_BASE_Waterbear_13_Jun17 : FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "425aaed4-879e-5caf-808b-14de98f628e8"
		date = "2017-06-23"
		modified = "2023-12-05"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_waterbear.yar#L219-L243"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b34c3d643309b8bbaa122a753e7f58dd9340cfa33962dbab1454c8080afd1664"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "734e5972ab5ac1e9bc5470c666a55e0d2bd57c4e2ea2da11dc9bf56fb2ea6f23"
		hash2 = "8bde3f71575aa0d5f5a095d9d0ea10eceadba38be888e10d3ca3776f7b361fe7"
		hash3 = "c4b3b0a7378bfc3824d4178fd7fb29475c42ab874d69abdfb4898d0bcd4f8ce1"

	strings:
		$s1 = "%WINDIR%\\PCHealth\\HelpCtr\\Binaries\\pchsvc.dll" fullword ascii
		$s2 = "brnew.exe" fullword ascii
		$s3 = "ChangeServiceConfig failed (%d)" fullword ascii
		$s4 = "Proxy %d:%s %d" fullword ascii
		$s5 = "win9807.tmp" fullword ascii
		$s7 = "Service stopped successfully" fullword ascii
		$s8 = "current dns:%s" fullword ascii
		$s9 = "%c%u|%u|%u|%u|%u|" fullword ascii
		$s10 = "[-]send %d: " fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 4 of them )
}
