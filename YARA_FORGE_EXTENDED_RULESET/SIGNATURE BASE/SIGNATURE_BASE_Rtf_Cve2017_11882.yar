rule SIGNATURE_BASE_Rtf_Cve2017_11882 : malicious exploit cve_2017_1182
{
	meta:
		description = "Attempts to identify the exploit CVE 2017 11882"
		author = "John Davison"
		id = "b6c59cf1-52e4-5c9e-b3c3-d973d52736e3"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/exploit_cve_2017_11882.yar#L20-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "51cf2a6c0c1a29abca9fd13cb22421da"
		logic_hash = "37a65f086d393aae3dc88b3dd2520fff6e96b92fd6ae1be0a110f4eb826ae12d"
		score = 60
		quality = 81
		tags = ""

	strings:
		$headers = { 31 63 30 30 30 30 30 30  30 32 30 30 ?? ?? ?? ??
                     61 39 30 30 30 30 30 30  ?? ?? ?? ?? ?? ?? ?? ??
                     ?? ?? ?? ?? ?? ?? ?? ??  ?? ?? ?? ?? ?? ?? ?? ??
                     ?? ?? ?? ?? ?? ?? ?? ??  30 33 30 31 30 31 30 33
                     ?? ?? }
		$font = { 30 61 30 31 30 38 35 61  35 61 }
		$winexec = { 31 32 30 63 34 33 30 30 }

	condition:
		all of them and @font>@headers and @winexec==@font+((5+44)*2)
}
