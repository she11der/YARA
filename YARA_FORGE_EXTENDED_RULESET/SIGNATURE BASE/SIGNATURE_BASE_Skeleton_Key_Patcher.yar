rule SIGNATURE_BASE_Skeleton_Key_Patcher
{
	meta:
		description = "Skeleton Key Patcher from Dell SecureWorks Report http://goo.gl/aAk3lN"
		author = "Dell SecureWorks Counter Threat Unit"
		id = "a2805cce-7605-58a4-85ce-9dff5586858e"
		date = "2015-01-13"
		modified = "2023-12-05"
		reference = "http://goo.gl/aAk3lN"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_skeletonkey.yar#L3-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "451b77152e38a120bd8d8a832f0f7c003974113ead18aabfe043a332fb1f484c"
		score = 70
		quality = 85
		tags = ""

	strings:
		$target_process = "lsass.exe" wide
		$dll1 = "cryptdll.dll"
		$dll2 = "samsrv.dll"
		$name = "HookDC.dll"
		$patched1 = "CDLocateCSystem"
		$patched2 = "SamIRetrievePrimaryCredentials"
		$patched3 = "SamIRetrieveMultiplePrimaryCredentials"

	condition:
		all of them
}
