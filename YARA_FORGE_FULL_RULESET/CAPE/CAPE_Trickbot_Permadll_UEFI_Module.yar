rule CAPE_Trickbot_Permadll_UEFI_Module
{
	meta:
		description = "Detects TrickBot Banking module permaDll"
		author = "@VK_Intel | Advanced Intelligence"
		id = "ba104164-0a1a-5a4c-8312-7653f7818e96"
		date = "2023-02-07"
		modified = "2023-02-07"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/TrickBot.yar#L22-L38"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		hash = "491115422a6b94dc952982e6914adc39"
		logic_hash = "564055f56fd19bed8900e6d451ba050b4e9013a9208a3bdc3d3d563567d225d2"
		score = 75
		quality = 70
		tags = ""

	strings:
		$module_cfg = "moduleconfig"
		$str_imp_01 = "Start"
		$str_imp_02 = "Control"
		$str_imp_03 = "FreeBuffer"
		$str_imp_04 = "Release"
		$module = "user_platform_check.dll"
		$intro_routine = { 83 ec 40 8b ?? ?? ?? 53 8b ?? ?? ?? 55 33 ed a3 ?? ?? ?? ?? 8b ?? ?? ?? 56 57 89 ?? ?? ?? a3 ?? ?? ?? ?? 39 ?? ?? ?? ?? ?? 75 ?? 8d ?? ?? ?? 89 ?? ?? ?? 50 6a 40 8d ?? ?? ?? ?? ?? 55 e8 ?? ?? ?? ?? 85 c0 78 ?? 8b ?? ?? ?? 85 ff 74 ?? 47 57 e8 ?? ?? ?? ?? 8b f0 59 85 f6 74 ?? 57 6a 00 56 e8 ?? ?? ?? ?? 83 c4 0c eb ??}

	condition:
		6 of them
}
