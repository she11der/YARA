rule SIGNATURE_BASE_Fourelementsword_Resn32Dll
{
	meta:
		description = "Detects FourElementSword Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "3e1f6d8d-53ea-542f-ba49-39b4c86f3124"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_four_element_sword.yar#L139-L154"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"
		logic_hash = "9658ae3d1267993551cfb939f75f3d78de18cbeb2f524c2576b849103f3cacdc"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\Release\\BypassUAC.pdb" ascii
		$s2 = "\\ResN32.dll" wide
		$s3 = "Eupdate" fullword wide

	condition:
		all of them
}
