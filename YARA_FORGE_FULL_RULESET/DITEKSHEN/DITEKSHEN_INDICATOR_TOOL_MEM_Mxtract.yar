import "pe"

rule DITEKSHEN_INDICATOR_TOOL_MEM_Mxtract : FILE
{
	meta:
		description = "Detects mXtract, a linux-based tool that dumps memory for offensive pentration testing and can be used to scan memory for private keys, ips, and passwords using regexes."
		author = "ditekSHen"
		id = "e8c5e5b3-aa98-5f7f-9410-3efeef725f41"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L182-L195"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8271722c3b8f4458d20cf874d37e87e3b1fde701205ff54f0360fb87f717fc3f"
		score = 50
		quality = 69
		tags = "FILE"

	strings:
		$s1 = "_ZN18process_operations10get_rangesEv" fullword ascii
		$s2 = "_ZN4misc10write_dumpESsSs" fullword ascii
		$s3 = "_ZTVNSt8__detail13_Scanner_baseE" fullword ascii
		$s4 = "Running as root is recommended as not all PIDs will be scanned" fullword ascii
		$s5 = "ERROR ATTACHING TO PROCESS" fullword ascii
		$s6 = "ERROR SCANNING MEMORY RANGE" fullword ascii

	condition:
		( uint32(0)==0x464c457f or uint16(0)==0x457f) and 3 of them
}
