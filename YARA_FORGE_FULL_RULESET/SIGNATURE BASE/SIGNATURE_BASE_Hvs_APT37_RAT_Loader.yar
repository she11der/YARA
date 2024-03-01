import "pe"

rule SIGNATURE_BASE_Hvs_APT37_RAT_Loader
{
	meta:
		description = "BLINDINGCAN RAT loader named iconcash.db used by APT37"
		author = "Marc Stroebel"
		id = "6c3e8465-d607-59bf-85fc-5abbef71fb1c"
		date = "2020-12-15"
		modified = "2023-12-05"
		reference = "https://us-cert.cisa.gov/ncas/analysis-reports/ar20-232a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_lazarus_dec20.yar#L52-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b70e66d387e42f5f04b69b9eb15306036702ab8a50b16f5403289b5388292db9"
		logic_hash = "241f2683adc29e8aca30ae24278f3703fef0fed6b276dae488fdb32c167af1c9"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	condition:
		(pe.version_info["OriginalFilename"] contains "MFC_DLL.dll") and (pe.exports("SMain") and pe.exports("SMainW"))
}
