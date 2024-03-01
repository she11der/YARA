rule SIGNATURE_BASE_Webshell_C99_Shell_Ci_Biz_Was_Here_C100_V_Xxx
{
	meta:
		description = "Web Shell"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L2508-L2527"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ccc3cb553f7b5d089a43612d48522cc4a66b4a8ab433321ae1a716a8fa57b62c"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "f2fa878de03732fbf5c86d656467ff50"
		hash2 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash3 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash4 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash5 = "048ccc01b873b40d57ce25a4c56ea717"

	strings:
		$s8 = "else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\""

	condition:
		all of them
}
