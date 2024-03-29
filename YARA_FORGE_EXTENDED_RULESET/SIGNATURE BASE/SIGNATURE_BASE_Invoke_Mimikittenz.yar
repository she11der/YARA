rule SIGNATURE_BASE_Invoke_Mimikittenz : FILE
{
	meta:
		description = "Detects Mimikittenz - file Invoke-mimikittenz.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "6dcf3d0a-302b-520c-97c6-fd843c8a25b9"
		date = "2016-07-19"
		modified = "2023-12-05"
		reference = "https://github.com/putterpanda/mimikittenz"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_mimikittenz.yar#L10-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f0410a0290d09d3574854b55ffe578f6f799368e14677b581cd65d18700a8656"
		score = 90
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "14e2f70470396a18c27debb419a4f4063c2ad5b6976f429d47f55e31066a5e6a"

	strings:
		$x1 = "[mimikittenz.MemProcInspector]" ascii
		$s1 = "PROCESS_ALL_ACCESS = PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION |" fullword ascii
		$s2 = "IntPtr processHandle = MInterop.OpenProcess(MInterop.PROCESS_WM_READ | MInterop.PROCESS_QUERY_INFORMATION, false, process.Id);" fullword ascii
		$s3 = "&email=.{1,48}&create=.{1,2}&password=.{1,22}&metadata1=" ascii
		$s4 = "[DllImport(\"kernel32.dll\", SetLastError = true)]" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <60KB and 2 of them ) or $x1
}
