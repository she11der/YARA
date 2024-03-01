rule SIGNATURE_BASE_MAL_RANSOM_SH_Esxi_Attacks_Feb23_1 : FILE
{
	meta:
		description = "Detects script used in ransomware attacks exploiting and encrypting ESXi servers - file encrypt.sh"
		author = "Florian Roth"
		id = "7178dbe4-f573-5279-a23e-9bab8ae8b743"
		date = "2023-02-04"
		modified = "2023-12-05"
		reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-14"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/mal_ransom_esxi_attacks_feb23.yar#L6-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1143ee36603f604874432ee280314a9f62ffe64e58ec5cd4eb114b7b175b365a"
		score = 85
		quality = 60
		tags = "FILE"
		hash1 = "10c3b6b03a9bf105d264a8e7f30dcab0a6c59a414529b0af0a6bd9f1d2984459"

	strings:
		$x1 = "/bin/find / -name *.log -exec /bin/rm -rf {} \\;" ascii fullword
		$x2 = "/bin/touch -r /etc/vmware/rhttpproxy/config.xml /bin/hostd-probe.sh" ascii fullword
		$x3 = "grep encrypt | /bin/grep -v grep | /bin/wc -l)" ascii fullword
		$s1 = "## ENCRYPT" ascii fullword
		$s2 = "/bin/find / -name *.log -exec /bin" ascii fullword

	condition:
		uint16(0)==0x2123 and filesize <10KB and (1 of ($x*) or 2 of them ) or 3 of them
}
