import "pe"

rule SIGNATURE_BASE_Bypassuacdll_6
{
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		id = "5be27053-446f-5ea3-a242-2661aeffa3df"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1000-L1011"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
		logic_hash = "3cb89875ddf79a3709aeb58149e228e03b9fb43fa1565aab5ece743857b4cc71"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s3 = "BypassUacDLL.dll" fullword wide
		$s4 = "AFX_IDP_COMMAND_FAILURE" fullword ascii

	condition:
		all of them
}
