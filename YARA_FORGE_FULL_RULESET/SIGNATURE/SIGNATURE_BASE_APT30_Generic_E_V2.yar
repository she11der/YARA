rule SIGNATURE_BASE_APT30_Generic_E_V2 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "40897687-fb17-568e-9907-e9588a53bbe0"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L519-L535"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "eca53a9f6251ddf438508b28d8a483f91b99a3fd"
		logic_hash = "25a7e5780f56b4f9cfb76494926c446a39a88bef2cda82b31e6de2b85c5edbda"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Nkfvtyvn}duf_Z}{Ys" fullword ascii
		$s1 = "Nkfvtyvn}*Zrswru1i" fullword ascii
		$s2 = "Nkfvtyvn}duf_Z}{V" fullword ascii
		$s3 = "Nkfvtyvn}*ZrswrumT\\b" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
