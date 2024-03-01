rule SIGNATURE_BASE_UACME_Akagi
{
	meta:
		description = "Rule to detect UACMe - abusing built-in Windows AutoElevate backdoor"
		author = "Florian Roth (Nextron Systems)"
		id = "7979129e-99a3-522a-8285-9061e1e2bd41"
		date = "2015-05-14"
		modified = "2023-12-05"
		reference = "https://github.com/hfiref0x/UACME"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/exploit_uac_elevators.yar#L35-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e10f39837a53dcc6d301d21a69fca965aeca0a07cfc832a9a0142b08d280f955"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "edd2138bbd9e76c343051c6dc898054607f2040a"
		hash2 = "e3a919ccc2e759e618208ededa8a543954d49f8a"

	strings:
		$x1 = "UACMe injected, Fubuki at your service." wide fullword
		$x3 = "%temp%\\Hibiki.dll" fullword wide
		$x4 = "[UCM] Cannot write to the target process memory." fullword wide
		$s1 = "%systemroot%\\system32\\cmd.exe" wide
		$s2 = "D:(A;;GA;;;WD)" wide
		$s3 = "%systemroot%\\system32\\sysprep\\sysprep.exe" fullword wide
		$s4 = "/c wusa %ws /extract:%%windir%%\\system32" fullword wide
		$s5 = "Fubuki.dll" ascii fullword
		$l1 = "ntdll.dll" ascii
		$l2 = "Cabinet.dll" ascii
		$l3 = "GetProcessHeap" ascii
		$l4 = "WriteProcessMemory" ascii
		$l5 = "ShellExecuteEx" ascii

	condition:
		(1 of ($x*)) or (3 of ($s*) and all of ($l*))
}
