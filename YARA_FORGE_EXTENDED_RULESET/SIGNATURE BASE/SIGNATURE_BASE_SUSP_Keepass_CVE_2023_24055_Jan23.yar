rule SIGNATURE_BASE_SUSP_Keepass_CVE_2023_24055_Jan23 : CVE_2023_24055 FILE
{
	meta:
		description = "Detects suspicious triggers defined in the Keepass configuration file, which could be indicator of the exploitation of CVE-2023-24055"
		author = "Florian Roth (Nextron Systems)"
		id = "4ff1a93f-f7f0-528d-9e07-402e321a0ffe"
		date = "2023-01-25"
		modified = "2023-12-05"
		reference = "https://github.com/alt3kx/CVE-2023-24055_PoC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/expl_keepass_cve_2023_24055.yar#L22-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4ed3eee86baf3dddfe423795491a5a94c02df3f4a7525efa6f2436e19197e55b"
		score = 60
		quality = 85
		tags = "CVE-2023-24055, FILE"

	strings:
		$a1 = "<TriggerCollection xmlns:xsi=" ascii wide
		$s1 = "<Action>" ascii wide
		$s2 = "<Parameter>" ascii wide

	condition:
		filesize <200KB and $a1 and all of ($s*)
}
