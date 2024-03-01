import "pe"

rule DITEKSHEN_INDICATOR_TOOL_PWS_Lazagne : FILE
{
	meta:
		description = "Detects LaZagne post-exploitation password stealing tool. It is typically embedded with malware in the binary resources."
		author = "ditekSHen"
		id = "68bc50b0-a64f-50b6-bfbf-a26a4d0970ef"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L3-L20"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "af4427174c1026204dc9c71878c5125efdf190328840b65fe4a69277a16fe7d2"
		score = 75
		quality = 50
		tags = "FILE"

	strings:
		$s1 = "blaZagne.exe.manifest" fullword ascii
		$S2 = "opyi-windows-manifest-filename laZagne.exe.manifest" fullword ascii
		$s3 = "lazagne.softwares.windows." ascii
		$s4 = "lazagne.softwares.sysadmin." ascii
		$s5 = "lazagne.softwares.php." ascii
		$s6 = "lazagne.softwares.memory." ascii
		$s7 = "lazagne.softwares.databases." ascii
		$s8 = "lazagne.softwares.browsers." ascii
		$s9 = "lazagne.config.write_output(" fullword ascii
		$s10 = "lazagne.config." ascii

	condition:
		uint16(0)==0x5a4d and any of them
}
