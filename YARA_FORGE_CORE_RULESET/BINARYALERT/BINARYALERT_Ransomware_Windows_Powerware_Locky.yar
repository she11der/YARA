rule BINARYALERT_Ransomware_Windows_Powerware_Locky
{
	meta:
		description = "PowerWare Ransomware"
		author = "@fusionrace"
		id = "8a1a56af-7a9d-54ed-90b9-daf33735ee1e"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://researchcenter.paloaltonetworks.com/2016/07/unit42-powerware-ransomware-spoofing-locky-malware-family/"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/ransomware/windows/ransomware_windows_powerware_locky.yara#L1-L17"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		hash = "3433a4da9d8794709630eb06afd2b8c1"
		logic_hash = "64de34755f706a9fd4c876c473eed4f8922a4450c7ef135b0ab5e49c67363baf"
		score = 75
		quality = 78
		tags = ""

	strings:
		$s0 = "ScriptRunner.dll" fullword ascii wide
		$s1 = "ScriptRunner.pdb" fullword ascii wide
		$s2 = "fixed.ps1" fullword ascii wide

	condition:
		all of them
}
