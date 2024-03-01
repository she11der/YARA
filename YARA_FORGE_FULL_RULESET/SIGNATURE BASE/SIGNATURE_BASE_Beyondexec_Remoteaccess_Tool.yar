import "pe"

rule SIGNATURE_BASE_Beyondexec_Remoteaccess_Tool : FILE
{
	meta:
		description = "Detects BeyondExec Remote Access Tool - file rexesvr.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "fd68cb45-a46f-53d7-bf52-8f7bd3636d0d"
		date = "2017-03-17"
		modified = "2023-12-05"
		reference = "https://goo.gl/BvYurS"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3634-L3652"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6f21ddf04ab0d29549c3d07a45afb3e7648a15b0c81f88b8d7ccccc436ba4084"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3d3e3f0708479d951ab72fa04ac63acc7e5a75a5723eb690b34301580747032c"

	strings:
		$x1 = "\\BeyondExecV2\\Server\\Release\\Pipes.pdb" ascii
		$x2 = "\\\\.\\pipe\\beyondexec%d-stdin" fullword ascii
		$x3 = "Failed to create dispatch pipe. Do you have another instance running?" fullword ascii
		$op1 = { 83 e9 04 72 0c 83 e0 03 03 c8 ff 24 85 80 6f 40 }
		$op2 = { 6a 40 33 c0 59 bf e0 d8 40 00 f3 ab 8d 0c 52 c1 }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and (1 of ($x*) or all of ($op*))) or (3 of them )
}
