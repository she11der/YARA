import "pe"
import "math"

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_Boombox_May21_1
{
	meta:
		description = "Detects BoomBox malware as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		id = "fe964f3e-1cda-5f16-838f-dd7b23cd5651"
		date = "2021-05-27"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt29_nobelium_may21.yar#L130-L143"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "02e4a1c88c5d5567c2c4098f60107d66ace9deaf03c480f15615f7f85a7c620c"
		score = 85
		quality = 85
		tags = ""

	strings:
		$xa1 = "123do3y4r378o5t34onf7t3o573tfo73" ascii wide fullword
		$xa2 = "1233t04p7jn3n4rg" ascii wide fullword

	condition:
		1 of them
}
