rule SIGNATURE_BASE_Nirsoft_Netresview : FILE
{
	meta:
		description = "Detects NirSoft NetResView - utility that displays the list of all network resources"
		author = "Florian Roth (Nextron Systems)"
		id = "bf786432-3ecf-510e-8d95-50aff09826ce"
		date = "2016-06-04"
		modified = "2023-12-05"
		reference = "https://goo.gl/Mr6M2J"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_irongate.yar#L67-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "56c3c7a98bcefa609ee604ea0d7d3f4dd237d91a9439eeed66e0d6f3a20dfdd0"
		score = 40
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "83f0352c14fa62ae159ab532d85a2b481900fed50d32cc757aa3f4ccf6a13bee"

	strings:
		$s1 = "NetResView.exe" fullword wide
		$s2 = "2005 - 2013 Nir Sofer" wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
