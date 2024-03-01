import "pe"

rule SIGNATURE_BASE_IMPLANT_3_V1
{
	meta:
		description = "X-Agent/CHOPSTICK Implant by APT28"
		author = "US CERT"
		id = "d539bb31-18b2-5cf5-b994-daecd5f8c771"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L425-L442"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4c7b6c76bc10784abf96cc71b34ffc9a9de569fd536505528752221d22b26629"
		score = 85
		quality = 85
		tags = ""

	strings:
		$STR1 = ">process isn't exist<" ascii wide
		$STR2 = "shell\\open\\command=\"System Volume Information\\USBGuard.exe\" install" ascii wide
		$STR3 = "User-Agent: Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0" ascii wide
		$STR4 = "webhp?rel=psy&hl=7&ai=" ascii wide
		$STR5 = {0f b6 14 31 88 55 ?? 33 d2 8b c1 f7 75 ?? 8b 45 ?? 41 0f b6 14
         02 8a 45 ?? 03 fa}

	condition:
		any of them
}
