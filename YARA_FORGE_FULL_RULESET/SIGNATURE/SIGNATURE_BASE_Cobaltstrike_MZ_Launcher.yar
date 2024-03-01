rule SIGNATURE_BASE_Cobaltstrike_MZ_Launcher
{
	meta:
		description = "Detects CobaltStrike MZ header ReflectiveLoader launcher"
		author = "yara@s3c.za.net"
		id = "461a4741-11c5-53d9-b8e1-52d64cfe755b"
		date = "2021-07-08"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_cobaltstrike_evasive.yar#L297-L307"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "aa188546db138dffdcdbf6538367b5d5bc37638a2784b24b7fcd913c15e56072"
		score = 75
		quality = 85
		tags = ""

	strings:
		$mz_launcher = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D }

	condition:
		$mz_launcher
}
