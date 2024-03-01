import "pe"

rule SIGNATURE_BASE_Unpack_Rar_Folder_Injectt
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "cc7d1a36-1214-5a14-8589-9eb2339a8700"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1953-L1976"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "80f39e77d4a34ecc6621ae0f4d5be7563ab27ea6"
		logic_hash = "f9d682a9438f49cf8292c33e680537d8c2137b8cba2670430b92d0a620de85b9"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "%s -Install                          -->To Install The Service" fullword ascii
		$s1 = "Explorer.exe" fullword ascii
		$s2 = "%s -Start                            -->To Start The Service" fullword ascii
		$s3 = "%s -Stop                             -->To Stop The Service" fullword ascii
		$s4 = "The Port Is Out Of Range" fullword ascii
		$s7 = "Fail To Set The Port" fullword ascii
		$s11 = "\\psapi.dll" ascii
		$s20 = "TInject.Dll" fullword ascii
		$x1 = "Software\\Microsoft\\Internet Explorer\\WinEggDropShell" fullword ascii
		$x2 = "injectt.exe" fullword ascii

	condition:
		(1 of ($x*)) and (3 of ($s*))
}
