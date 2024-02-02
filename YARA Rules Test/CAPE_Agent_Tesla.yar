rule CAPE_Agent_Tesla
{
	meta:
		description = "Detecting HTML strings used by Agent Tesla malware"
		author = "Stormshield"
		id = "5383994b-357d-539b-89b1-53be238f759d"
		date = "2023-10-31"
		modified = "2023-10-31"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/5db57762ada4ddb5b47cdb2c13150917f53241c0/data/yara/CAPE/AgentTesla.yar#L1-L17"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/5db57762ada4ddb5b47cdb2c13150917f53241c0/LICENSE"
		logic_hash = "3945754129dcc58e0abfd7485f5ff0c0afdd1078ae2cf164ca8f59a6f79db1be"
		score = 75
		quality = 70
		tags = ""
		version = "1.0"

	strings:
		$html_username = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
		$html_pc_name = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
		$html_os_name = "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: " wide ascii
		$html_os_platform = "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: " wide ascii
		$html_clipboard = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide ascii

	condition:
		3 of them
}