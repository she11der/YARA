import "pe"

rule DITEKSHEN_INDICATOR_TOOL_CNC_Shootback : FILE
{
	meta:
		description = "detects Python executable for CnC communication via reverse tunnels. Used by MuddyWater group."
		author = "ditekSHen"
		id = "fb608115-6d9f-5640-88be-674e53b07126"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L43-L62"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "996cabd4965164cb844cee1ab1e2894fc2b4fac14d4e660c456b494c5cbd0688"
		score = 75
		quality = 50
		tags = "FILE"

	strings:
		$s1 = "PYTHON27.DLL" fullword wide
		$s2 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyR" fullword ascii
		$s3 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyt" fullword ascii
		$s4 = "subprocess.pyc" fullword ascii
		$s5 = "MyGetProcAddress(%p, %p(%s)) -> %p" fullword ascii
		$p1 = "Slaver(this pc):" ascii
		$p2 = "Master(another public server):" ascii
		$p3 = "Master(this pc):" ascii
		$p4 = "running as slaver, master addr: {} target: {}R/" fullword ascii
		$p5 = "Customer(this pc): " ascii
		$p6 = "Customer(any internet user):" ascii
		$p7 = "the actual traffic is:  customer <--> master(1.2.3.4) <--> slaver(this pc) <--> ssh(this pc)" fullword ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($s*) and 2 of ($p*))
}
