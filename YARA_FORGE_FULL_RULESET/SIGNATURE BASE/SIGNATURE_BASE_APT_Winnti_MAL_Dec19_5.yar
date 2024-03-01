import "pe"

rule SIGNATURE_BASE_APT_Winnti_MAL_Dec19_5
{
	meta:
		description = "Detects Winnti malware"
		author = "Unknown"
		id = "2a8f28e6-5a01-5a2f-b89b-9c34163afcda"
		date = "2019-12-06"
		modified = "2023-12-05"
		reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_winnti.yar#L237-L264"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "977d11fbb7cf4678d4da179c43d5566520ee97ac528e269a9b985e5bc75641b7"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a1 = "-k netsvcs" ascii
		$a2 = "svchost.exe" ascii fullword
		$a3 = "%SystemRoot%\\System32\\ntoskrnl.exe" ascii
		$a4 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411015}" ascii
		$a5 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411014}" ascii
		$a6 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411016}" ascii
		$a7 = "cmd.exe" wide
		$a8 = ",XML" wide
		$a9 = "\\rundll32.exe" wide
		$a10 = "\\conhost.exe" wide
		$a11 = "\\cmd.exe" wide
		$a12 = "NtQueryInformationProcess" ascii
		$a13 = "Detours!" ascii fullword
		$a14 = "Loading modified build of detours library designed for MPC-HC player (http://sourceforge.net/projects/mpc-hc/)" ascii
		$a15 = "CONOUT$" wide fullword
		$a16 = { C6 0? E9 4? 8? 4? 05 [2] 89 4? 01 }

	condition:
		(12 of ($a*))
}
