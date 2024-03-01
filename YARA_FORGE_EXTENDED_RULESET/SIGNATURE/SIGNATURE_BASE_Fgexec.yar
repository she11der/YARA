import "pe"

rule SIGNATURE_BASE_Fgexec : FILE
{
	meta:
		description = "Detects a tool used by APT groups - file fgexec.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8ffe47b9-81a8-5eb4-b46f-db9d23682de4"
		date = "2016-09-08"
		modified = "2023-12-05"
		reference = "http://goo.gl/igxLyF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3346-L3362"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "3672255d7829520aa8ca792519f645b86fe4244a16652a960375f23baa7d32b3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8697897bee415f213ce7bc24f22c14002d660b8aaffab807490ddbf4f3f20249"

	strings:
		$x1 = "\\Release\\fgexec.pdb" ascii
		$x2 = "fgexec Remote Process Execution Tool" fullword ascii
		$x3 = "fgexec CallNamedPipe failed" fullword ascii
		$x4 = "fizzgig and the mighty foofus.net team" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of ($x*)) or (3 of them )
}
