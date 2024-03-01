rule SIGNATURE_BASE_Waterbug_Wipbot_2013_Core_PDF : FILE
{
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 core PDF"
		author = "Symantec Security Response"
		id = "2e8ccce9-d8ba-573d-b532-76d8e2ed5442"
		date = "2015-01-22"
		modified = "2023-12-05"
		reference = "http://t.co/rF35OaAXrl"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_waterbug.yar#L3-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a854926a4a98eb1d13a582b4ff4504b9740b8bbe7aa6b5192aeb4d2438a58926"
		score = 75
		quality = 60
		tags = "FILE"

	strings:
		$a = /\+[A-Za-z]{1}\. _ _ \$\+[A-Za-z]{1}\. _ \$ _ \+/
		$b = /\+[A-Za-z]{1}\.\$\$\$ _ \+/

	condition:
		uint32(0)==0x46445025 and #a>150 and #b>200
}
