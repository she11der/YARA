rule VOLEXITY_Webshell_Java_Behinder_Shellservice : Webshells Commodity
{
	meta:
		description = "Looks for artifacts generated (generally seen in .class files) related to the Behinder framework."
		author = "threatintel@volexity.com"
		id = "21c1e3e9-d048-5c60-9c21-8e54b27f359a"
		date = "2022-03-18"
		modified = "2022-07-28"
		reference = "https://github.com/MountCloud/BehinderClientSource/blob/master/src/main/java/net/rebeyond/behinder/core/ShellService.java"
		source_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L1-L23"
		license_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/LICENSE.txt"
		logic_hash = "373a8d4ef81e9bbbf1f24ebf0389e7da4b73f88786cc8e1d286ccc9f4c36debc"
		score = 75
		quality = 30
		tags = ""
		hash1 = "9a9882f9082a506ed0fc4ddaedd50570c5762deadcaf789ac81ecdbb8cf6eff2"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 1

	strings:
		$s1 = "CONNECT" ascii fullword
		$s2 = "DISCONNECT" ascii fullword
		$s3 = "socket_" ascii fullword
		$s4 = "targetIP" ascii fullword
		$s5 = "targetPort" ascii fullword
		$s6 = "socketHash" ascii fullword
		$s7 = "extraData" ascii fullword

	condition:
		all of them
}
