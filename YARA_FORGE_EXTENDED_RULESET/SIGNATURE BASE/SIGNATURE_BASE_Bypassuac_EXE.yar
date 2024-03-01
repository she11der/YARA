import "pe"

rule SIGNATURE_BASE_Bypassuac_EXE
{
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		id = "b88aded5-7dfb-5cdf-bb42-cd8b069259e0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1013-L1027"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
		logic_hash = "0283efd6866ed9417f2d255715f04c0ed6d7a89befce6a3a52c22ac06593c0bd"
		score = 75
		quality = 60
		tags = ""

	strings:
		$s1 = "Wole32.dll" wide
		$s3 = "System32\\migwiz" wide
		$s4 = "System32\\migwiz\\CRYPTBASE.dll" wide
		$s5 = "Elevation:Administrator!new:" wide
		$s6 = "BypassUac" wide

	condition:
		all of them
}
