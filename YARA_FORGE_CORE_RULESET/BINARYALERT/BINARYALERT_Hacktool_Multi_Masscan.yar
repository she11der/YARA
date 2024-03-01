rule BINARYALERT_Hacktool_Multi_Masscan
{
	meta:
		description = "masscan is a performant port scanner, it produces results similar to nmap"
		author = "@mimeframe"
		id = "adb2bb07-2a1a-5eb5-8049-b3f8e6cba48a"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/robertdavidgraham/masscan"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/multi/hacktool_multi_masscan.yara#L1-L17"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "b35e481f73b1c1722056157f8348e2e06bb109c094b948fc6be2d9a7df070a7f"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "EHLO masscan" fullword wide ascii
		$a2 = "User-Agent: masscan/" wide ascii
		$a3 = "/etc/masscan/masscan.conf" fullword wide ascii
		$b1 = "nmap(%s): unsupported. This code will never do DNS lookups." wide ascii
		$b2 = "nmap(%s): unsupported, we do timing WAY different than nmap" wide ascii
		$b3 = "[hint] I've got some local priv escalation 0days that might work" wide ascii
		$b4 = "[hint] VMware on Macintosh doesn't support masscan" wide ascii

	condition:
		all of ($a*) or any of ($b*)
}
