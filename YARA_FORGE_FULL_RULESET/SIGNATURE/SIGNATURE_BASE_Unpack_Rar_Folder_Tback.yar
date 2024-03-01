import "pe"

rule SIGNATURE_BASE_Unpack_Rar_Folder_Tback
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file TBack.DLL"
		author = "Florian Roth (Nextron Systems)"
		id = "f672f987-0d43-53df-8338-084907b6da16"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2041-L2069"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "30fc9b00c093cec54fcbd753f96d0ca9e1b2660f"
		logic_hash = "89f978742ab952b727a9a8dbab0cd88cfc07440e8c4f974dcfa14ed630083761"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Redirect SPort RemoteHost RPort       -->Port Redirector" fullword ascii
		$s1 = "http://IP/a.exe a.exe                 -->Download A File" fullword ascii
		$s2 = "StopSniffer                           -->Stop Pass Sniffer" fullword ascii
		$s3 = "TerminalPort Port                     -->Set New Terminal Port" fullword ascii
		$s4 = "Example: Http://12.12.12.12/a.exe abc.exe" fullword ascii
		$s6 = "Create Password Sniffering Thread Successfully. Status:Logging" fullword ascii
		$s7 = "StartSniffer NIC                      -->Start Sniffer" fullword ascii
		$s8 = "Shell                                 -->Get A Shell" fullword ascii
		$s11 = "DeleteService ServiceName             -->Delete A Service" fullword ascii
		$s12 = "Disconnect ThreadNumber|All           -->Disconnect Others" fullword ascii
		$s13 = "Online                                -->List All Connected IP" fullword ascii
		$s15 = "Getting The UserName(%c%s%c)-->ID(0x%s) Successfully" fullword ascii
		$s16 = "Example: Set REG_SZ Test Trojan.exe" fullword ascii
		$s18 = "Execute Program                       -->Execute A Program" fullword ascii
		$s19 = "Reboot                                -->Reboot The System" fullword ascii
		$s20 = "Password Sniffering Is Not Running" fullword ascii

	condition:
		4 of them
}
