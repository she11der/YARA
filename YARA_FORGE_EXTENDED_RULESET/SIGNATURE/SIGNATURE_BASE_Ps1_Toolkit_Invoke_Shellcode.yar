rule SIGNATURE_BASE_Ps1_Toolkit_Invoke_Shellcode : FILE
{
	meta:
		description = "Auto-generated rule - file Invoke-Shellcode.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "193d64b6-ffba-55fb-ab95-9c78552b8d68"
		date = "2016-09-04"
		modified = "2023-12-05"
		reference = "https://github.com/vysec/ps1-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_powershell_toolkit.yar#L51-L69"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "03e9a8c5e45781d73fd13c331d82802a18e4255b506e896019d6f08c5a67dedf"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "24abe9f3f366a3d269f8681be80c99504dea51e50318d83ee42f9a4c7435999a"

	strings:
		$s1 = "Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
		$s2 = "Get-ProcAddress kernel32.dll OpenProcess" fullword ascii
		$s3 = "msfpayload windows/exec CMD=\"cmd /k calc\" EXITFUNC=thread C | sed '1,6d;s/[\";]//g;s/\\\\/,0/g' | tr -d '\\n' | cut -c2- " fullword ascii
		$s4 = "inject shellcode into" ascii
		$s5 = "Injecting shellcode" ascii

	condition:
		( uint16(0)==0xbbef and filesize <90KB and 1 of them ) or (3 of them )
}
