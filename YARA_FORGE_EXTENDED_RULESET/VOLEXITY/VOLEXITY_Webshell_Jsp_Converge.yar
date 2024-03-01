rule VOLEXITY_Webshell_Jsp_Converge : Webshell
{
	meta:
		description = "File upload webshell observed in incident involving compromise of Confluence server."
		author = "threatintel@volexity.com"
		id = "2a74678e-cb00-567c-a2e0-2e095f3e5ee8"
		date = "2022-06-01"
		modified = "2022-06-06"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L1-L15"
		license_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/LICENSE.txt"
		logic_hash = "bb48516342eddd48c35e6db0eb74f95e116dc723503552b99ba721b5bdb391e5"
		score = 75
		quality = 80
		tags = ""
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s1 = "if (request.getParameter(\"name\")!=null && request.getParameter(\"name\").length()!=0){" ascii

	condition:
		$s1
}
