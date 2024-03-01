rule SIGNATURE_BASE_Ps1_Toolkit_Invoke_Mimikatz : FILE
{
	meta:
		description = "Auto-generated rule - file Invoke-Mimikatz.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "7c0252a1-fbe4-5519-949b-285073abb21f"
		date = "2016-09-04"
		modified = "2023-12-05"
		reference = "https://github.com/vysec/ps1-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_powershell_toolkit.yar#L71-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0bca6245befb5183f6a45406823c45267b0a31fb0d4505606b98025f6494f2cc"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"

	strings:
		$s1 = "Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
		$s2 = "ps | where { $_.Name -eq $ProcName } | select ProcessName, Id, SessionId" fullword ascii
		$s3 = "privilege::debug exit" ascii
		$s4 = "Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" fullword ascii
		$s5 = "Invoke-Mimikatz -DumpCreds" fullword ascii
		$s6 = "| Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002" fullword ascii

	condition:
		( uint16(0)==0xbbef and filesize <10000KB and 1 of them ) or (3 of them )
}
