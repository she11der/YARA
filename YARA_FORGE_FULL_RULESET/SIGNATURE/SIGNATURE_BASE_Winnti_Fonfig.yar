rule SIGNATURE_BASE_Winnti_Fonfig : FILE
{
	meta:
		description = "Winnti sample - file fonfig.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ca3c186c-0286-5b9b-9585-7680336c8c3d"
		date = "2017-01-25"
		modified = "2023-12-05"
		reference = "https://goo.gl/VbvJtL"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_winnti_ms_report_201701.yar#L10-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "715892268431bf76cf9bf0bdbeaf4129befdc590b5b2dcae479d95dfe77561a4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2c9882854a60c624ecf6b62b6c7cc7ed04cf4a29814aa5ed1f1a336854697641"

	strings:
		$s1 = "mciqtz.exe" fullword wide
		$s2 = "knat9y7m" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
