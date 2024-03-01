rule SIGNATURE_BASE_Custom_Ssh_Backdoor_Server
{
	meta:
		description = "Custome SSH backdoor based on python and paramiko - file server.py"
		author = "Florian Roth (Nextron Systems)"
		id = "eccf705b-b2c3-5af6-ab86-70292089812b"
		date = "2015-05-14"
		modified = "2022-08-18"
		reference = "https://goo.gl/S46L3o"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_backdoor_ssh_python.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0953b6c2181249b94282ca5736471f85d80d41c9"
		logic_hash = "7bb142b69a75003e8f26d462c0895a3d807d5c326684e83d756178a3b91669dc"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "command= raw_input(\"Enter command: \").strip('n')" fullword ascii
		$s1 = "print '[-] (Failed to load moduli -- gex will be unsupported.)'" fullword ascii
		$s2 = "print '[-] Listen/bind/accept failed: ' + str(e)" fullword ascii

	condition:
		2 of them
}
