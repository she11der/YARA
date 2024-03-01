import "pe"

rule SIGNATURE_BASE_Bypassuac_3
{
	meta:
		description = "Auto-generated rule - file BypassUacDll.dll"
		author = "yarGen Yara Rule Generator"
		id = "407a8e12-1160-584d-94c8-7aa78e29c754"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L969-L982"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1974aacd0ed987119999735cad8413031115ce35"
		logic_hash = "cf3183ff4562f2962f87bc594c1710c73c113fa1d49fa56f7a3ff391ba4b9003"
		score = 75
		quality = 60
		tags = ""

	strings:
		$s0 = "BypassUacDLL.dll" fullword wide
		$s1 = "\\Release\\BypassUacDll" ascii
		$s3 = "Win7ElevateDLL" fullword wide
		$s7 = "BypassUacDLL" fullword wide

	condition:
		3 of them
}
