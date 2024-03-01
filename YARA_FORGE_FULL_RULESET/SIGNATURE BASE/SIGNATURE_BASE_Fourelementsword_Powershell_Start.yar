rule SIGNATURE_BASE_Fourelementsword_Powershell_Start
{
	meta:
		description = "Detects FourElementSword Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "62affc03-a408-5d8f-99da-58dead8646c5"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_four_element_sword.yar#L123-L137"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"
		logic_hash = "7b1986845d97dcd11c8baddb0b49350ad30c6fff98840275befef4ad0b906b54"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "start /min powershell C:\\\\ProgramData\\\\wget.exe" ascii
		$s1 = "start /min powershell C:\\\\ProgramData\\\\iuso.exe" fullword ascii

	condition:
		1 of them
}
