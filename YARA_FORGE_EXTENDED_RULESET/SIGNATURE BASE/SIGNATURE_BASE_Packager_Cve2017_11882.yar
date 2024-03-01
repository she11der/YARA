rule SIGNATURE_BASE_Packager_Cve2017_11882 : CVE_2017_11882 FILE
{
	meta:
		description = "Attempts to exploit CVE-2017-11882 using Packager"
		author = "Rich Warren"
		id = "57ff395e-e56a-5e63-bde6-f3cef038fcd6"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/rxwx/CVE-2017-11882/blob/master/packager_exec_CVE-2017-11882.py"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/exploit_cve_2017_11882.yar#L41-L56"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "94e0c70e8140bb7fa3d184447617b534a8b9a24cdad535e6818be9662f0b9144"
		score = 60
		quality = 79
		tags = "CVE-2017-11882, FILE"

	strings:
		$font = { 30 61 30 31 30 38 35 61  35 61 }
		$equation = { 45 71 75 61 74 69 6F 6E 2E 33 }
		$package = { 50 61 63 6b 61 67 65 }
		$header_and_shellcode = /03010[0,1][0-9a-fA-F]{108}00/ ascii nocase

	condition:
		uint32be(0)==0x7B5C7274 and all of them
}
