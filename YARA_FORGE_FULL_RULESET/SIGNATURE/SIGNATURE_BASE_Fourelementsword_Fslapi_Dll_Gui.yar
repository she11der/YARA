rule SIGNATURE_BASE_Fourelementsword_Fslapi_Dll_Gui : FILE
{
	meta:
		description = "Detects FourElementSword Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "1cc73eaf-7463-5070-97e5-6ea4c7735371"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_four_element_sword.yar#L106-L121"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
		logic_hash = "909b187f864a240268d0ffcef904b85cd1eaad97dd3a3a808aad58968fbb76c2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "fslapi.dll.gui" fullword wide
		$s2 = "ImmGetDefaultIMEWnd" fullword ascii
		$s3 = "RichOX" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <12KB and all of them )
}
