rule VOLEXITY_Apt_Win_Applejeus_D_Oct22 : Lazarus
{
	meta:
		description = "Detected AppleJeus unpacked samples."
		author = "threatintel@volexity.com"
		id = "80d2821b-a437-573e-9e9d-bf79f9422cc9"
		date = "2022-11-10"
		modified = "2022-12-01"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L65-L83"
		license_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/LICENSE.txt"
		logic_hash = "23c0642e5be15a75a39d089cd52f2f14d633f7af6889140b9ec6e53c5c023974"
		score = 75
		quality = 80
		tags = ""
		hash1 = "a241b6611afba8bb1de69044115483adb74f66ab4a80f7423e13c652422cb379"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$reg = "Software\\Bitcoin\\Bitcoin-Qt"
		$pattern = "%s=%d&%s=%s&%s=%s&%s=%d"
		$exec = " \"%s\", RaitingSetupUI "
		$http = "Accept: */*" wide

	condition:
		all of them
}
