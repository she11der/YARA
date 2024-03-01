rule SIGNATURE_BASE_Fourelementsword_Config_File
{
	meta:
		description = "Detects FourElementSword Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "488a2344-3d8d-5769-aca8-9e14f38f5eb0"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_four_element_sword.yar#L11-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f05cd0353817bf6c2cab396181464c31c352d6dea07e2d688def261dd6542b27"
		logic_hash = "680e50998093e63a4e3c7d5338ac149efef83cdb41ceb4ce0245e8bd2ab99b84"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "01,,hccutils.dll,2" fullword ascii
		$s1 = "RegisterDlls=OurDll" fullword ascii
		$s2 = "[OurDll]" fullword ascii
		$s3 = "[DefaultInstall]" fullword ascii
		$s4 = "Signature=\"$Windows NT$\"" fullword ascii

	condition:
		4 of them
}
