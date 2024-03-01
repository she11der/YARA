rule SIGNATURE_BASE_Sphinx_Moth_H2T : FILE
{
	meta:
		description = "sphinx moth threat group file h2t.dat"
		author = "Kudelski Security - Nagravision SA (modified by Florian Roth)"
		id = "62d14efd-7d0b-5f66-9e78-74f3f9e2fd5b"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "www.kudelskisecurity.com"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sphinx_moth.yar#L28-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7aca260d415de84cf432b18385db6a9768a036e3bd0a9aa8ded4a1bfcad26d0c"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "%s <proxy ip> <proxy port> <target ip> <target port> <cmd> [arg1 cmd] ... [argX cmd]" fullword ascii
		$s1 = "[-] Error in connection() %d - %s" fullword ascii
		$s2 = "[-] Child process exit." fullword ascii
		$s3 = "POST http://%s:%s/ HTTP/1.1" fullword ascii
		$s4 = "pipe() to" fullword ascii
		$s5 = "pipe() from" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <156KB and ($x1 or all of ($s*))
}
