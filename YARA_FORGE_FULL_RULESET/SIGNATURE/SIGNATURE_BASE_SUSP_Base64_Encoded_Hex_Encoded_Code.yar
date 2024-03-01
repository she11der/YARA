rule SIGNATURE_BASE_SUSP_Base64_Encoded_Hex_Encoded_Code
{
	meta:
		description = "Detects hex encoded code that has been base64 encoded"
		author = "Florian Roth (Nextron Systems)"
		id = "2cfd278f-ff45-5e23-b552-dad688ab303b"
		date = "2019-04-29"
		modified = "2023-12-05"
		reference = "https://www.nextron-systems.com/2019/04/29/spotlight-threat-hunting-yara-rule-example/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_obfuscation.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f1451e2dd0e4e70a0f39f609331762cce369642e9fadbef83d932da2a0a6c60b"
		score = 65
		quality = 85
		tags = ""

	strings:
		$x1 = { 78 34 4e ?? ?? 63 65 44 ?? ?? 58 48 67 }
		$x2 = { 63 45 44 ?? ?? 58 48 67 ?? ?? ?? 78 34 4e }
		$fp1 = "Microsoft Azure Code Signp$"

	condition:
		1 of ($x*) and not 1 of ($fp*)
}
